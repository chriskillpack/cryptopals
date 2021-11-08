package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
)

// Returns data padded to the blocksize amount using PKCS7
func pkcs7Padding(data []byte, blocksize int) []byte {
	pad := blocksize - (len(data) % blocksize)
	if pad > 255 {
		panic("Cannot represent padding amount in a byte")
	}
	padding := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(data, padding...)
}

func encryptECB(out, in []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}

	for i := 0; i < len(in); i += cipher.BlockSize() {
		cipher.Encrypt(out[i:], in[i:])
	}
}

// WARNING: This has not been tested yet
// iv = Initialization Vector, the contents are overwritten
func encryptCBC(out, in, iv []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}
	if len(iv) != cipher.BlockSize() {
		panic("IV incorrect length")
	}

	bs := cipher.BlockSize()
	for i := 0; i < len(in); i += bs {
		scratch := xor(in[i:i+bs], iv)
		cipher.Encrypt(out[i:i+bs], scratch)
		copy(iv, out[i:i+bs])
	}
}

// iv = Initialization Vector, the contents are overwritten
func decryptCBC(out, in, iv []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}
	if len(iv) != cipher.BlockSize() {
		panic("IV incorrect length")
	}

	bs := cipher.BlockSize()
	for i := 0; i < len(in); i += bs {
		cipher.Decrypt(out[i:i+bs], in[i:i+bs])
		scratch := xor(out[i:i+bs], iv)
		copy(out[i:i+bs], scratch)
		copy(iv, in[i:i+bs])
	}
}

func randomAESkey() ([]byte, error) {
	key := make([]byte, 16)
	n, err := crand.Read(key)
	if err != nil {
		panic(err)
	}
	if n != 16 {
		return nil, fmt.Errorf("did not get 16 random bytes")
	}
	return key, nil
}

func encryptionOracle() func([]byte) []byte {
	prefix := make([]byte, rand.Intn(5)+5)
	crand.Read(prefix)
	suffix := make([]byte, rand.Intn(5)+5)
	crand.Read(suffix)

	key, _ := randomAESkey()
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		// ENCRYPT(prefix | in | suffix) where | denotes concatenation
		body := pkcs7Padding(append(append(prefix, in...), suffix...), cipher.BlockSize())

		if rand.Int()&1 == 0 {
			encryptECB(body, body, cipher)
		} else {
			iv := make([]byte, cipher.BlockSize())
			crand.Read(iv)
			encryptCBC(body, body, iv, cipher)
		}

		return body
	}
}

var (
	consistentECBKeyOnce sync.Once
	consistentECBKey     []byte
)

func consistentECB(plaintext, secret []byte) ([]byte, error) {
	consistentECBKeyOnce.Do(func() {
		var err error
		consistentECBKey, err = randomAESkey()
		if err != nil {
			panic(err)
		}
	})

	cipher, err := aes.NewCipher(consistentECBKey)
	if err != nil {
		return nil, err
	}
	bs := cipher.BlockSize()

	contents := append(plaintext, []byte(secret)...)
	out := pkcs7Padding(contents, bs)
	encryptECB(out, out, cipher)

	return out, nil
}

func profileFor(email string) (string, error) {
	// Sanitize email of '&' and '='
	san := strings.ReplaceAll(email, "&", "")
	san = strings.ReplaceAll(san, "=", "")

	profile := url.Values{}
	profile.Set("email", san)
	profile.Set("uid", "10")
	profile.Set("role", "user")
	path, err := url.PathUnescape(profile.Encode())
	if err != nil {
		return "", err
	}

	return path, nil
}
