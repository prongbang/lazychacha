# lazychacha

Lazy ChaCha20-Poly1305 in golang on [golang.org/x/crypto](golang.org/x/crypto).

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/lazychacha)](https://goreportcard.com/report/github.com/prongbang/lazychacha)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Algorithm details

- Key exchange: X25519
- Encryption: ChaCha20
- Authentication: Poly1305

### Install

```
go get github.com/prongbang/lazychacha
```

### Benchmark

```shell
BenchmarkEncrypt-10    	 1347146	       872.2 ns/op	     864 B/op	       5 allocs/op
BenchmarkDecrypt-10    	 2088066	       577.9 ns/op	     544 B/op	       4 allocs/op
```

### How to use

- Generate KeyPair

```go
keyPair := lazychacha.NewKeyPair()
```

- Key Exchange

```go
clientKp := lazychacha.NewKeyPair()
serverKp := lazychacha.NewKeyPair()

serverKx := serverKp.Exchange(clientKp.Pk)
clientKx := clientKp.Exchange(serverKp.Pk)
```

- Shared Key

```go
serverSharedKey, _ := serverKx.Secret()
clientSharedKey, _ := clientKx.Secret()
```

- Encrypt

```go
lazyChacha := lazychacha.New()
sharedKey, _ := clientKx.Secret()
key, _ := hex.DecodeString(sharedKey)
plaintext := "text"
ciphertext, err := lazyChacha.Encrypt(plaintext, key)
```

- Decrypt

```go
lazyChacha := lazychacha.New()
sharedKey, _ := serverKx.Secret()
key, _ := hex.DecodeString(sharedKey)
ciphertext := "f6a1bd8"
plaintext, err := lazyChacha.Decrypt(ciphertext, key)
```
