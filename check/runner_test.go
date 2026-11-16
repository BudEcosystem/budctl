package check

import (
	"context"
	"testing"
	"time"
)

// A check that depends on its own group must see what the rest of the group
// recorded. platform.openshift-version raced platform.distribution and
// reported "not an OpenShift cluster" on OpenShift.
func TestRunOrdersAGroupsDependentsAfterTheRestOfIt(t *testing.T) {
	saved := registry
	registry = map[string]*Check{}
	defer func() { registry = saved }()

	Register(&Check{
		ID: "platform.a-reader", Group: "platform", DependsOn: []string{"platform"},
		Run: func(_ context.Context, c *Ctx) Result {
			ch := Lookup("platform.a-reader")
			if !c.Platform.IsOpenShift() {
				return ch.Skip("not an OpenShift cluster")
			}
			return ch.Pass("saw the detected distribution")
		},
	})
	Register(&Check{
		ID: "platform.z-writer", Group: "platform",
		Run: func(_ context.Context, c *Ctx) Result {
			time.Sleep(20 * time.Millisecond)
			c.Platform.Distribution = DistOpenShift
			return Lookup("platform.z-writer").Pass("detected")
		},
	})

	for _, r := range Run(context.Background(), NewCtx(), Selection{}, nil) {
		if r.ID == "platform.a-reader" && r.Status() != "PASS" {
			t.Fatalf("the dependent check ran before the distribution was detected: %s", r.Summary)
		}
	}
}
