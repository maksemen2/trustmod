package gomod

import (
	"context"
	"strings"
	"time"
)

func Verify(ctx context.Context, dir string, timeout time.Duration) (bool, string) {
	out, err := Go(ctx, dir, timeout, "mod", "verify")
	if err != nil {
		return false, strings.TrimSpace(out + "\n" + err.Error())
	}
	return true, strings.TrimSpace(out)
}
