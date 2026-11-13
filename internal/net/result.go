package net

import "time"

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
