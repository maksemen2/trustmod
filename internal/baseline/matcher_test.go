package baseline

import (
	"testing"
	"time"
)

func TestAcceptsFinding(t *testing.T) {
	b := Baseline{AcceptedFindings: []AcceptedFinding{{Module: "example.com/mod", Version: "v0.1.0", Code: "TM-VER-005"}}}
	if !b.AcceptsFinding("example.com/mod", "v0.1.0", "TM-VER-005", time.Now()) {
		t.Fatalf("finding was not accepted")
	}
}
