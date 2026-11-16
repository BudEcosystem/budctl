package checks

import "testing"

func TestStOversized(t *testing.T) {
	for capacity, want := range map[string]bool{
		"":      false,
		"junk":  false,
		"1Gi":   false,
		"10Gi":  false, // GCE pd-balanced rounds a 1Gi claim up to this
		"11Gi":  true,
		"499Gi": true, // OpenShift Local's hostpath CSI reports the host disk
	} {
		if got := stOversized(capacity); got != want {
			t.Errorf("stOversized(%q) = %v, want %v", capacity, got, want)
		}
	}
}
