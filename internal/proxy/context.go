package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// ContextStorageName gives a backend a per-instance opaque host directory
// name (its log folders use it).
// Callers validate backend IDs before using the legacy empty namespace form.
func ContextStorageName(namespace, backendID string) string {
	if namespace == "" {
		return backendID
	}
	mac := hmac.New(sha256.New, []byte(namespace))
	_, _ = mac.Write([]byte("slot\x00" + backendID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func newSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
