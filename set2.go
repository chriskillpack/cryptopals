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
)

// OracleFunc represents a function that returns the encrypted or decrypted
// contents of in
type OracleFunc func(in []byte) []byte

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

// Builds a 'fragment' dictionary using the encryption oracle to encrypt every
// possible input block of the form:
//   XXXXRRRRRRRRRRR? where X is the constant, R=recovered secret and ? will
//                    take every value from [0,255].
// This function assumes that the length of recovered is one character less than
// the room we are leaving at the end. offset is the slice index of the
// beginning of the bs sized block that the secret character is being extracted
// from.
// TODO: pass arguments using a struct?
func fragmentDict(recovered string, oracle OracleFunc, offset, room, pad, bs int) map[string]byte {
	dictionary := make(map[string]byte)
	for i := 0; i <= 255; i++ {
		fragment := bytes.Repeat([]byte{192}, pad+bs-room)
		fragment = append(fragment, []byte(recovered)...)
		fragment = append(fragment, byte(i))
		out := oracle(fragment)
		dictionary[string(out[offset:offset+bs])] = byte(i)
	}

	return dictionary
}

func encryptionOracle() OracleFunc {
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

// secret will be concatenated to in prior to encryption. Passing nil or an
// empty byte slice to
func consistentECBOracle(secret []byte) OracleFunc {
	key, _ := randomAESkey()
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		body := pkcs7Padding(append(in, secret...), cipher.BlockSize())
		encryptECB(body, body, cipher)
		return body
	}
}

func encryptDecryptECBOracle() (enc, dec OracleFunc) {
	key, _ := randomAESkey()
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
			body := pkcs7Padding(in, cipher.BlockSize())
			encryptECB(body, body, cipher)
			return body
		}, func(in []byte) []byte {
			body := make([]byte, len(in))
			copy(body, in)
			decryptECB(body, body, cipher)
			// TODO: discard padding?
			return body
		}
}

func randomPrefixSecretECBOracle(secret []byte) OracleFunc {
	key, _ := randomAESkey()
	cipher, _ := aes.NewCipher(key)

	prefix := make([]byte, rand.Intn(32)+10)
	crand.Read(prefix)

	return func(in []byte) []byte {
		body := pkcs7Padding(append(append(prefix, in...), secret...), cipher.BlockSize())
		encryptECB(body, body, cipher)
		return body
	}
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
