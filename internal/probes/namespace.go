// Package probes owns the only part of budctl that writes to the cluster.
// Everything here is created in one labelled namespace and removed on the way
// out, including on interrupt (FRD-020 §6).
package probes

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/BudEcosystem/budctl/internal/adapters"
)

const (
	// ManagedBy labels every object budctl creates so `budctl cleanup` can find
	// leftovers from a run that was killed before its deferred cleanup ran.
	ManagedByKey   = "app.kubernetes.io/managed-by"
	ManagedByValue = "budctl"
	NamePrefix     = "budctl-readiness-"
)

// Runner creates the probe namespace lazily: a run that never reaches a probe
// check must not leave a namespace behind.
type Runner struct {
	kube       *adapters.Kube
	name       string
	keep       bool
	created    bool
	suffix     string
	pullSecret string
}

func NewRunner(k *adapters.Kube, explicitNamespace, suffix string, keep bool) *Runner {
	name := explicitNamespace
	if name == "" {
		name = NamePrefix + suffix
	}
	return &Runner{kube: k, name: name, keep: keep, suffix: suffix}
}

func (r *Runner) Namespace() string { return r.name }

// Ensure creates the namespace if it does not exist yet.
func (r *Runner) Ensure(ctx context.Context) error {
	if r.created || r.kube == nil {
		return nil
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   r.name,
			Labels: map[string]string{ManagedByKey: ManagedByValue},
		},
	}
	_, err := r.kube.Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("create probe namespace %s: %w", r.name, err)
	}
	r.created = true
	return nil
}

// Cleanup removes the namespace. It is safe to call more than once and takes a
// fresh context, because the run's context is usually already cancelled by the
// time cleanup runs.
func (r *Runner) Cleanup() {
	if !r.created || r.keep || r.kube == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = r.kube.Clientset.CoreV1().Namespaces().Delete(ctx, r.name, metav1.DeleteOptions{})
	r.created = false
}

func (r *Runner) Kept() bool { return r.keep && r.created }

// PodSpec describes a probe pod in the few terms the checks actually vary.
type PodSpec struct {
	Name       string
	Image      string
	Command    []string
	Resources  map[string]string // e.g. {"nvidia.com/gpu": "1"}
	Volumes    []corev1.Volume
	Mounts     []corev1.VolumeMount
	Timeout    time.Duration
	PullSecret string
}

// PodOutcome separates the ways a probe can fail, because their remedies are
// completely different: never scheduled, started and failed, or ran and exited.
type PodOutcome struct {
	Scheduled bool
	Started   bool
	Succeeded bool
	Logs      string
	Phase     string
	Reason    string
	Events    []string
}

// RunPod creates a pod, waits for it to finish, collects its logs and deletes
// it. The returned outcome distinguishes a scheduling failure from a start
// failure from a non-zero exit.
func (r *Runner) RunPod(ctx context.Context, spec PodSpec) (PodOutcome, error) {
	out := PodOutcome{}
	if err := r.Ensure(ctx); err != nil {
		return out, err
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	limits := corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}
	requests := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("10m"),
		corev1.ResourceMemory: resource.MustParse("32Mi"),
	}
	for k, v := range spec.Resources {
		q, err := resource.ParseQuantity(v)
		if err != nil {
			continue
		}
		limits[corev1.ResourceName(k)] = q
		requests[corev1.ResourceName(k)] = q
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: r.name,
			Labels:    map[string]string{ManagedByKey: ManagedByValue},
		},
		Spec: corev1.PodSpec{
			RestartPolicy:         corev1.RestartPolicyNever,
			ActiveDeadlineSeconds: ptr(int64(timeout.Seconds()) + 30),
			Volumes:               spec.Volumes,
			Containers: []corev1.Container{{
				Name:         "probe",
				Image:        spec.Image,
				Command:      spec.Command,
				VolumeMounts: spec.Mounts,
				Resources:    corev1.ResourceRequirements{Limits: limits, Requests: requests},
			}},
		},
	}
	if spec.PullSecret != "" {
		pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: spec.PullSecret}}
	}

	client := r.kube.Clientset.CoreV1().Pods(r.name)
	if _, err := client.Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return out, fmt.Errorf("create probe pod: %w", err)
	}
	defer func() {
		delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !r.keep {
			_ = client.Delete(delCtx, spec.Name, metav1.DeleteOptions{})
		}
	}()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p, err := client.Get(ctx, spec.Name, metav1.GetOptions{})
		if err == nil {
			out.Phase = string(p.Status.Phase)
			if p.Spec.NodeName != "" {
				out.Scheduled = true
			}
			for _, cs := range p.Status.ContainerStatuses {
				if cs.State.Running != nil || cs.State.Terminated != nil {
					out.Started = true
				}
				if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
					out.Reason = cs.State.Waiting.Reason + ": " + cs.State.Waiting.Message
				}
				if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
					out.Reason = cs.State.Terminated.Reason
				}
			}
			switch p.Status.Phase {
			case corev1.PodSucceeded:
				out.Succeeded = true
			case corev1.PodFailed:
				out.Succeeded = false
			}
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				out.Logs, _ = r.kube.PodLogs(ctx, r.name, spec.Name)
				out.Events = r.events(ctx, spec.Name)
				return out, nil
			}
			if !out.Scheduled {
				for _, cond := range p.Status.Conditions {
					if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
						out.Reason = cond.Reason + ": " + cond.Message
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			out.Events = r.events(ctx, spec.Name)
			return out, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	out.Logs, _ = r.kube.PodLogs(context.Background(), r.name, spec.Name)
	out.Events = r.events(ctx, spec.Name)
	return out, fmt.Errorf("probe pod did not finish within %s", timeout)
}

// events surfaces the Kubernetes Event verbatim, which is almost always the
// actual explanation for a stuck probe.
func (r *Runner) events(ctx context.Context, name string) []string {
	out := []string{}
	list, err := r.kube.Clientset.CoreV1().Events(r.name).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + name,
	})
	if err != nil {
		return out
	}
	for _, e := range list.Items {
		out = append(out, fmt.Sprintf("%s: %s", e.Reason, e.Message))
	}
	return out
}

// ProvisionPVC creates a claim with a consumer pod and reports whether it
// bound. The consumer is mandatory: a WaitForFirstConsumer class never binds
// without one, and testing without it would report every such class as broken.
func (r *Runner) ProvisionPVC(ctx context.Context, name, storageClass, size string, timeout time.Duration) (bound bool, phase string, events []string, err error) {
	if err := r.Ensure(ctx); err != nil {
		return false, "", nil, err
	}
	q, err := resource.ParseQuantity(size)
	if err != nil {
		return false, "", nil, err
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: r.name,
			Labels: map[string]string{ManagedByKey: ManagedByValue},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: q},
			},
		},
	}
	if storageClass != "" {
		pvc.Spec.StorageClassName = &storageClass
	}
	pvcClient := r.kube.Clientset.CoreV1().PersistentVolumeClaims(r.name)
	if _, err := pvcClient.Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		return false, "", nil, fmt.Errorf("create probe PVC: %w", err)
	}
	defer func() {
		delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !r.keep {
			_ = pvcClient.Delete(delCtx, name, metav1.DeleteOptions{})
		}
	}()

	// The consumer pod exists solely to trigger binding on a
	// WaitForFirstConsumer class; it exits immediately.
	consumer := PodSpec{
		Name:    name + "-consumer",
		Image:   "busybox:1.36",
		Command: []string{"/bin/sh", "-c", "echo bound"},
		Timeout: timeout,
		Volumes: []corev1.Volume{{
			Name: "probe",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: name},
			},
		}},
		Mounts: []corev1.VolumeMount{{Name: "probe", MountPath: "/probe"}},
	}
	go func() { _, _ = r.RunPod(context.Background(), consumer) }()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, gerr := pvcClient.Get(ctx, name, metav1.GetOptions{})
		if gerr == nil {
			phase = string(got.Status.Phase)
			if got.Status.Phase == corev1.ClaimBound {
				return true, phase, nil, nil
			}
		}
		select {
		case <-ctx.Done():
			return false, phase, r.pvcEvents(ctx, name), ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return false, phase, r.pvcEvents(ctx, name), nil
}

func (r *Runner) pvcEvents(ctx context.Context, name string) []string {
	out := []string{}
	list, err := r.kube.Clientset.CoreV1().Events(r.name).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + name,
	})
	if err != nil {
		return out
	}
	for _, e := range list.Items {
		out = append(out, fmt.Sprintf("%s: %s", e.Reason, e.Message))
	}
	return out
}

func ptr[T any](v T) *T { return &v }
