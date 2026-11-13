package checks

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/check"
	"github.com/BudEcosystem/budctl/k8s"
	"github.com/BudEcosystem/budctl/output"
)

// The golden tests pin what `budctl check` prints for whole runs against
// synthetic clusters: the table, the JSON report and the verdict that decides
// the exit code. Only the groups that make no network call are selected, so
// the output is the same on every machine.
//
// Run `go test ./check/checks -run Golden -update` to rewrite them.

var update = flag.Bool("update", false, "rewrite the golden files")

var offlineGroups = []string{"platform", "cluster", "nodes", "storage", "components", "gpu"}

func healthyVanilla() *fakeCluster {
	f := vanilla()
	for _, n := range []string{"n1", "n2", "n3"} {
		f.with("nodes", "", node(n)).
			withStats(n, k8s.NodeStats{Node: n, ImageFsCapacity: gib(400), ImageFsAvailable: gib(200)})
	}
	return f.
		with("storageclasses.storage.k8s.io", "", storageClass("standard", "rancher.io/local-path", true, true, nil)).
		with("ingressclasses.networking.k8s.io", "", ingressClass("traefik", "traefik.io/ingress-controller")).
		with("apiservices.apiregistration.k8s.io", "", apiService("v1beta1.metrics.k8s.io", true)).
		with("pods", "kube-system", pod("kube-system", "coredns-1", true))
}

func brokenVanilla() *fakeCluster {
	return vanilla().
		with("nodes", "", node("n1", notReady), node("n2", tainted), node("n3", arm64)).
		with("apiservices.apiregistration.k8s.io", "", apiService("v1beta1.metrics.k8s.io", false))
}

func healthyOpenShift() *fakeCluster {
	f := openShift()
	for _, n := range []string{"n1", "n2", "n3"} {
		f.with("nodes", "", node(n))
	}
	return f.
		with("storageclasses.storage.k8s.io", "", storageClass("gp3-csi", "ebs.csi.aws.com", true, true, nil)).
		with("clusteroperators.config.openshift.io", "", clusterOperator("ingress", true), clusterOperator("dns", true)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 2))
}

func TestGoldenCheck(t *testing.T) {
	for name, f := range map[string]*fakeCluster{
		"vanilla-healthy":   healthyVanilla(),
		"vanilla-broken":    brokenVanilla(),
		"openshift-healthy": healthyOpenShift(),
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := f.ctx(t)
			c.Opts.BudctlVersion = "golden"
			rep := check.Summarize(check.Run(ctx, c, check.Selection{Only: offlineGroups}, nil))
			rep.Stamp(c)
			for i := range rep.Results {
				rep.Results[i].Duration = 0
			}

			var table bytes.Buffer
			output.Table(&table, rep, output.Options{Verbose: true})
			assertGolden(t, name+".table.txt", table.Bytes())

			var js bytes.Buffer
			if err := output.JSON(&js, rep); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, name+".json", js.Bytes())

			var junit bytes.Buffer
			if err := output.JUnit(&junit, rep); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, name+".junit.xml", junit.Bytes())
		})
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
		for i := 0; i < len(w) && i < len(g); i++ {
			if w[i] != g[i] {
				t.Fatalf("%s differs at line %d:\n  - %s\n  + %s", name, i+1, w[i], g[i])
			}
		}
		t.Fatalf("%s differs in length: %d lines, want %d", name, len(g), len(w))
	}
}
