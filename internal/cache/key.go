package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func Key(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(strings.TrimSpace(p)))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
