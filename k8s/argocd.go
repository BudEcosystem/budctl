package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// The ArgoCD resources are addressed by their stable GVRs, not through
// discovery: a freshly installed CRD may not be in the discovery cache yet,
// and status polling must never read a cached list.
var (
	ApplicationGVR    = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	ApplicationSetGVR = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applicationsets"}
)

// ResourcesFinalizer makes ArgoCD delete an Application's resources before the
// Application itself goes.
const ResourcesFinalizer = "resources-finalizer.argocd.argoproj.io"

// ListFresh lists a resource straight from the API server. A missing CRD is
// reported as an error, so a caller can tell "no ArgoCD" from "no
// Applications".
func (k *Client) ListFresh(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]Object, error) {
	list, err := k.Dynamic.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]Object, 0, len(list.Items))
	for _, item := range list.Items {
		out = append(out, Object(item.Object))
	}
	return out, nil
}

// GetFresh reads one object from the API server; nil when it does not exist.
func (k *Client) GetFresh(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string) (Object, error) {
	u, err := k.Dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Object(u.Object), nil
}

// AddFinalizer adds a finalizer to an object, keeping any it already has.
func (k *Client) AddFinalizer(ctx context.Context, gvr schema.GroupVersionResource, namespace, name, finalizer string) error {
	o, err := k.GetFresh(ctx, gvr, namespace, name)
	if err != nil || o == nil {
		return err
	}
	finalizers := []string{}
	if meta, ok := o["metadata"].(map[string]any); ok {
		if list, ok := meta["finalizers"].([]any); ok {
			for _, f := range list {
				if s, _ := f.(string); s == finalizer {
					return nil
				} else if s != "" {
					finalizers = append(finalizers, s)
				}
			}
		}
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"finalizers": append(finalizers, finalizer)}})
	if err != nil {
		return err
	}
	_, err = k.Dynamic.Resource(gvr).Namespace(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// Delete deletes an object. With orphan set, objects it owns are kept.
// Deleting something already gone is not an error.
func (k *Client) Delete(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string, orphan bool) error {
	policy := metav1.DeletePropagationBackground
	if orphan {
		policy = metav1.DeletePropagationOrphan
	}
	err := k.Dynamic.Resource(gvr).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &policy})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete %s %s/%s: %w", gvr.Resource, namespace, name, err)
	}
	return nil
}

// PodLogTail returns the last lines of one container's log.
func (k *Client) PodLogTail(ctx context.Context, namespace, pod, container string, lines int64) ([]byte, error) {
	return k.Clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, TailLines: &lines}).DoRaw(ctx)
}
