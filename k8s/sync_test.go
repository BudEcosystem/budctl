package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeArgo answers sync requests with a scripted sequence of outcomes, the
// way ArgoCD's controller would update the Application, and records the
// operations budctl sent.
func fakeArgo(t *testing.T, outcomes []map[string]any) (*Client, *[]map[string]any) {
	t.Helper()
	app := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
		"metadata": map[string]any{"name": "e2e-bud", "namespace": "argocd"},
		"spec": map[string]any{"syncPolicy": map[string]any{
			"syncOptions": []any{"CreateNamespace=true", "ServerSideApply=true"},
		}},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{ApplicationGVR: "ApplicationList"}, app)
	var sent []map[string]any
	dyn.PrependReactor("patch", "applications", func(action k8stesting.Action) (bool, runtime.Object, error) {
		var patch map[string]any
		_ = json.Unmarshal(action.(k8stesting.PatchAction).GetPatch(), &patch)
		sent = append(sent, patch)
		n := len(sent) - 1
		if n >= len(outcomes) {
			n = len(outcomes) - 1
		}
		status := outcomes[n]
		status["operationState"].(map[string]any)["startedAt"] = fmt.Sprint(len(sent))
		obj := app.DeepCopy()
		obj.Object["status"] = status
		_ = dyn.Tracker().Update(ApplicationGVR, obj, "argocd")
		return true, obj, nil
	})
	return &Client{Dynamic: dyn}, &sent
}

func outcome(phase, sync, health, message string) map[string]any {
	return map[string]any{
		"operationState": map[string]any{"phase": phase, "message": message},
		"sync":           map[string]any{"status": sync},
		"health":         map[string]any{"status": health},
	}
}

func fastSync(t *testing.T) {
	poll, backoff, max := syncPoll, syncBackoff, syncBackoffMax
	syncPoll, syncBackoff, syncBackoffMax = time.Millisecond, time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { syncPoll, syncBackoff, syncBackoffMax = poll, backoff, max })
}

// A chart's webhook is not ready on the first pass; the sync must keep
// retrying rather than give up after a fixed few attempts.
func TestSyncRetriesTransientFailuresUntilHealthy(t *testing.T) {
	fastSync(t)
	webhook := outcome("Failed", "OutOfSync", "Missing", "failed calling webhook")
	client, sent := fakeArgo(t, []map[string]any{
		webhook, outcome("Failed", "OutOfSync", "Missing", "webhook still starting"), webhook,
		outcome("Failed", "OutOfSync", "Missing", "service not found"),
		outcome("Succeeded", "Synced", "Healthy", "ok"),
	})
	if err := client.SyncArgoApplication(context.Background(), "argocd", "e2e-bud", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 5 {
		t.Fatalf("sent %d sync requests, want 5", len(*sent))
	}
}

// ArgoCD takes a requested sync's options from the operation, so the
// Application's own CreateNamespace and ServerSideApply must be sent with it.
func TestSyncSendsTheApplicationsSyncOptions(t *testing.T) {
	fastSync(t)
	client, sent := fakeArgo(t, []map[string]any{outcome("Succeeded", "Synced", "Healthy", "ok")})
	if err := client.SyncArgoApplication(context.Background(), "argocd", "e2e-bud", time.Minute); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal((*sent)[0])
	if !strings.Contains(string(b), `"syncOptions":["CreateNamespace=true","ServerSideApply=true"]`) {
		t.Fatalf("sync request did not carry the Application's options: %s", b)
	}
}

// A failure that repeats unchanged is permanent; stop early.
func TestSyncGivesUpOnARepeatedFailure(t *testing.T) {
	fastSync(t)
	client, sent := fakeArgo(t, []map[string]any{outcome("Error", "Unknown", "Healthy", "401 Unauthorized")})
	err := client.SyncArgoApplication(context.Background(), "argocd", "e2e-bud", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "the same way") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("got %v", err)
	}
	if len(*sent) > 10 {
		t.Fatalf("kept retrying a permanent failure: %d attempts", len(*sent))
	}
}

// Every sync asks for a hard refresh, so a cached render failure is not
// served back to each retry.
func TestSyncRequestsAHardRefresh(t *testing.T) {
	fastSync(t)
	client, sent := fakeArgo(t, []map[string]any{outcome("Succeeded", "Synced", "Healthy", "ok")})
	if err := client.SyncArgoApplication(context.Background(), "argocd", "e2e-bud", time.Minute); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal((*sent)[0])
	if !strings.Contains(string(b), `"argocd.argoproj.io/refresh":"hard"`) {
		t.Fatalf("sync request did not ask for a hard refresh: %s", b)
	}
}
