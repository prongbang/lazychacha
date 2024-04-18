# lazychacha

Lazy ChaCha20-Poly1305 in golang.

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/lazychacha)](https://goreportcard.com/report/github.com/prongbang/lazychacha)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

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
key, _ := lazyChacha.RandomKey()
plaintext := "text"
ciphertext, err := lazyChacha.Encrypt(plaintext, key)
```

- Decrypt

```go
lazyChacha := lazychacha.New()
key := "e7de22e8"
ciphertext := "f6a1bd8"
plaintext, err := lazyChacha.Decrypt(ciphertext, key)
```