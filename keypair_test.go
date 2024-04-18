package lazychacha_test

import (
	"testing"

	"github.com/prongbang/lazychacha"
)

func TestKeyPair(t *testing.T) {
	// Generate KeyPair
	clientKp := lazychacha.NewKeyPair()
	serverKp := lazychacha.NewKeyPair()

	// Key Exchange
	serverKx := serverKp.Exchange(clientKp.Pk)
	clientKx := clientKp.Exchange(serverKp.Pk)

	// Shared Key
	serverSharedKey, _ := serverKx.Secret()
	clientSharedKey, _ := clientKx.Secret()

	if serverSharedKey != clientSharedKey {
		t.Errorf("Error %s != %s", serverSharedKey, clientSharedKey)
	}
}
