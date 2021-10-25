package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"sync"
)

const challenge12Suffix = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

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

// iv = Initialization Vectgsor, the contents are overwritten
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

func encryptionOracle(plaintext []byte) ([]byte, error) {
	before := rand.Intn(5) + 5
	after := rand.Intn(5) + 5
	ln := len(plaintext)

	key, err := randomAESkey()
	if err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := cipher.BlockSize()

	// With the size of the buffer known it can now be padded
	// The return value of pkcs7Padding will be a slice of 0 bytes
	// with pkcs7 padding at the end.
	out := pkcs7Padding(make([]byte, before+ln+after), bs)

	// Now the rest of the data can be filled in inplace.
	// First the random prefix
	n, err := crand.Read(out[:before])
	if n != before {
		return nil, err
	}
	// Then the plaintext body
	copy(out[before:], plaintext)
	// Finally the random suffix
	n, err = crand.Read(out[before+ln : before+ln+after])
	if n != after {
		return nil, err
	}

	iv := make([]byte, bs)
	for i := 0; i < len(out); i += bs {
		if rand.Int()&1 == 0 {
			// Encrypt ECB
			cipher.Encrypt(out[i:i+bs], out[i:i+bs])
		} else {
			// Encrypt CBC

			// Populate IV with random data
			n, err := crand.Read(iv)
			if n != len(iv) {
				return nil, err
			}
			encryptCBC(out[i:i+bs], out[i:i+bs], iv, cipher)
		}
	}

	return out, nil
}

var (
	consistentECBKeyOnce sync.Once
	consistentECBKey     []byte
)

func consistentECB(plaintext []byte) ([]byte, error) {
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

	decoded, err := base64.StdEncoding.DecodeString(challenge12Suffix)
	if err != nil {
		return nil, err
	}
	contents := append(plaintext, []byte(decoded)...)
	out := pkcs7Padding(contents, bs)

	for i := 0; i < len(out); i += bs {
		// Encrypt ECB
		cipher.Encrypt(out[i:i+bs], out[i:i+bs])
	}

	return out, nil
}
