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
	ciphertext, _ := lazyChacha.Encrypt(plaintext, key)
	fmt.Println(sharedKey)
	fmt.Println(ciphertext)
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d")
	ciphertext := "76627d3eded9ab4eea7877ae72e87b7c3f0556977bd344ce1831a3f90281b28ef866785552b48cded0e2dd6f38f9a429d3dc75667ab33a52cf1346b74fa4ebd99672781330d87ed1e6dffb0915ebaa04d12a3bfda33a21d5e27ae2d38df34659c41135e105afbe8a4462c047c9ada27598e6d04f015d07587bf2bad0b72b470adc79b52cee92bb68df"
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
