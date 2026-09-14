// Package adapters wraps every external system budctl talks to. Each call goes
// through here so it can be recorded and replayed in tests, and so that the
// checks never shell out: FRD-020 §9.1 requires no kubectl, helm, sops or age
// binary on the host.
package adapters

import "time"

// Credential is a registry or repository login.
type Credential struct {
	Username string
	Password string
}

// Object is one rendered Kubernetes manifest, kept as a generic map so a check
// can inspect any kind without budctl needing its Go type.
type Object map[string]any

func (o Object) Kind() string       { return str(o["kind"]) }
func (o Object) APIVersion() string { return str(o["apiVersion"]) }

func (o Object) Name() string {
	if m, ok := o["metadata"].(map[string]any); ok {
		return str(m["name"])
	}
	return ""
}

func (o Object) Namespace() string {
	if m, ok := o["metadata"].(map[string]any); ok {
		return str(m["namespace"])
	}
	return ""
}

func (o Object) Annotations() map[string]string { return o.metaMap("annotations") }
func (o Object) Labels() map[string]string      { return o.metaMap("labels") }

func (o Object) metaMap(field string) map[string]string {
	out := map[string]string{}
	m, ok := o["metadata"].(map[string]any)
	if !ok {
		return out
	}
	raw, ok := m[field].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range raw {
		out[k] = str(v)
	}
	return out
}

// Dig walks a nested manifest by key path, returning nil when any hop is absent
// so callers do not need a type switch at every level.
func (o Object) Dig(path ...string) any {
	var cur any = map[string]any(o)
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return cur
}

func (o Object) DigSlice(path ...string) []any {
	if v, ok := o.Dig(path...).([]any); ok {
		return v
	}
	return nil
}

func (o Object) DigString(path ...string) string { return str(o.Dig(path...)) }

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PodSpec returns the pod template spec for any workload kind, so capacity and
// image inventory code does not special-case Deployment vs CronJob.
func (o Object) PodSpec() map[string]any {
	switch o.Kind() {
	case "CronJob":
		if m, ok := o.Dig("spec", "jobTemplate", "spec", "template", "spec").(map[string]any); ok {
			return m
		}
	case "Pod":
		if m, ok := o.Dig("spec").(map[string]any); ok {
			return m
		}
	default:
		if m, ok := o.Dig("spec", "template", "spec").(map[string]any); ok {
			return m
		}
	}
	return nil
}

// Containers returns containers plus initContainers.
func (o Object) Containers() []map[string]any {
	ps := o.PodSpec()
	if ps == nil {
		return nil
	}
	out := []map[string]any{}
	for _, field := range []string{"containers", "initContainers"} {
		if list, ok := ps[field].([]any); ok {
			for _, c := range list {
				if cm, ok := c.(map[string]any); ok {
					out = append(out, cm)
				}
			}
		}
	}
	return out
}

// HTTPResult is the outcome of one probe. Reachable means the endpoint
// answered at all — for a registry a 401 is a reachability PASS, because it
// proves DNS, routing, TLS and a live service (FRD-020 D7).
type HTTPResult struct {
	Reachable  bool
	Status     int
	Err        string
	Latency    time.Duration
	TLSIssuer  string
	TLSExpiry  time.Time
	ServerTime time.Time
}
