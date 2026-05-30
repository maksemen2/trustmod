package analyze

import "testing"

func TestCompareVersionsUsesSemverOrdering(t *testing.T) {
	if got := compareVersions("v1.10.0", "v1.9.0"); got <= 0 {
		t.Fatalf("v1.10.0 should compare greater than v1.9.0, got %d", got)
	}
	if got := compareVersions("v1.9.0", "v1.10.0"); got >= 0 {
		t.Fatalf("v1.9.0 should compare lower than v1.10.0, got %d", got)
	}
}
