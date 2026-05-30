package gomod

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWithOfflineForcesGoNetworkOff(t *testing.T) {
	out, err := Go(WithOffline(context.Background()), t.TempDir(), 10*time.Second, "env", "GOPROXY", "GOSUMDB")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(out)
	if len(lines) < 2 || lines[0] != "off" || lines[1] != "off" {
		t.Fatalf("go env under offline context = %q, want GOPROXY/GOSUMDB off", out)
	}
}
