package lazychacha_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/prongbang/lazychacha"
)

var lazyChacha lazychacha.LazyChaCha

func init() {
	lazyChacha = lazychacha.New()
}

func TestRandomKey(t *testing.T) {
	key, _ := lazyChacha.RandomKey()
	if len(key) == 0 {
		t.Error("Error", key)
	}
}

func TestEncrypt(t *testing.T) {
	clientKeyPair := lazychacha.NewKeyPair()
	serverKeyPair := lazychacha.NewKeyPair()
	kxKeyPair := clientKeyPair.Exchange(serverKeyPair.Pk)
	sharedKey, _ := kxKeyPair.Secret()
	key, _ := hex.DecodeString(sharedKey)
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`
	ciphertext, err := lazyChacha.Encrypt(plaintext, key)
	fmt.Println(sharedKey)
	fmt.Println(ciphertext, err)
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("ad59ff86a894107ff31c0de8a8f98b2cb03977ecbe1287a23a5ce1b5df480a49")
	ciphertext := "51fed5fb713fbbd1dcaabc6b1a4d6eb50685879ee7dcd576beb42e197a1c7e245a8cc99a4a1f8b8782fb7f2f5f48151f80c8566a6cbe51ffffa0fcf85c1f6332c07cb7183426303797db252e859e5343a20e67fc3bec545b85869a7398ee12bff2dc66dc21f4a845c784deb9ecaf81c109f3f2bee868218b3fbb2b904d643bc3e8387deff3e3f0f6bd"
	plaintext, err := lazyChacha.Decrypt(ciphertext, key)
	fmt.Println(plaintext, err)
}

func BenchmarkEncrypt(b *testing.B) {
	key, _ := lazyChacha.RandomKey()
	plaintext := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`
	for i := 0; i < b.N; i++ {
		_, err := lazyChacha.Encrypt(plaintext, key)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := hex.DecodeString("ad59ff86a894107ff31c0de8a8f98b2cb03977ecbe1287a23a5ce1b5df480a49")
	ciphertext := "51fed5fb713fbbd1dcaabc6b1a4d6eb50685879ee7dcd576beb42e197a1c7e245a8cc99a4a1f8b8782fb7f2f5f48151f80c8566a6cbe51ffffa0fcf85c1f6332c07cb7183426303797db252e859e5343a20e67fc3bec545b85869a7398ee12bff2dc66dc21f4a845c784deb9ecaf81c109f3f2bee868218b3fbb2b904d643bc3e8387deff3e3f0f6bd"
	for i := 0; i < b.N; i++ {
		_, err := lazyChacha.Decrypt(ciphertext, key)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}
