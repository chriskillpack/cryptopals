package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
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

// stripped=nil,valid=false if the input has invalid padding
func removePkcs7Padding(data []byte) (stripped []byte, valid bool) {
	pad := data[len(data)-1]
	idx := len(data) - 2
	for ; idx > len(data)-int(pad)-1; idx-- {
		if data[idx] != pad {
			return nil, false
		}
	}
	idx++ // "back up" to last position
	out := make([]byte, idx)
	copy(out, data[:idx])
	return out, true
}

func encryptECB(out, in []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}

	for i := 0; i < len(in); i += cipher.BlockSize() {
		cipher.Encrypt(out[i:], in[i:])
	}
}

// out and in must overlap entirely or not at all.
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

// out and in must overlap entirely or not at all.
// iv = Initialization Vector, the contents are overwritten
func decryptCBC(out, in, iv []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}
	if len(iv) != cipher.BlockSize() {
		panic("IV incorrect length")
	}

	temp := make([]byte, 16) // YUCK, necessary to support out and in overlapping

	bs := cipher.BlockSize()
	for i := 0; i < len(in); i += bs {
		copy(temp, in[i:i+bs])
		cipher.Decrypt(out[i:i+bs], in[i:i+bs])
		copy(out[i:i+bs], xor(out[i:i+bs], iv))
		copy(iv, temp)
	}
}

func randomAESkey() []byte {
	key := make([]byte, 16)
	n, err := crand.Read(key)
	if err != nil {
		panic(err)
	}
	if n != 16 {
		return nil
	}
	return key
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

// recoverSecretFromECB applies the technique described in Set 2 / Challenge 12
// to brute force extract the appended secret from beneath ECB encryption.
// Returns empty string if it was unsuccessful.
// window = byte offset of first block after any oracle included prefix
// align = the byte distance from end of prefix to the next block boundary
func recoverSecretFromECB(oracle OracleFunc, secretLen, window, align, bs int) string {
	recovered := ""
outer:
	for {
		// Set 2 Challenge 12 explains how to extract the secret from the first
		// block. To extract the secret from the following blocks we repeat the
		// technique in each of the remaining blocks.
		for i := 0; i < bs; i++ {
			dict := fragmentDict(recovered, oracle, window, i+1, align, bs)
			fragment := bytes.Repeat([]byte{192}, align+(bs-(i+1)))
			out := oracle(fragment)
			b, ok := dict[string(out[window:window+bs])]
			if !ok {
				return ""
			}
			recovered += string(b)
			if len(recovered) == secretLen {
				break outer
			}
		}
		window += bs // Move to the next block
	}

	return recovered
}

func decryptCBCOracle(key []byte) OracleFunc {
	cipher, _ := aes.NewCipher(key)

	return func(in []byte) []byte {
		plaintext := make([]byte, len(in))
		iv := make([]byte, cipher.BlockSize())
		decryptCBC(plaintext, []byte(in), iv, cipher)
		return plaintext
	}
}

func encryptionOracle() OracleFunc {
	prefix := make([]byte, rand.Intn(5)+5)
	crand.Read(prefix)
	suffix := make([]byte, rand.Intn(5)+5)
	crand.Read(suffix)

	cipher, _ := aes.NewCipher(randomAESkey())

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
	cipher, _ := aes.NewCipher(randomAESkey())

	return func(in []byte) []byte {
		body := pkcs7Padding(append(in, secret...), cipher.BlockSize())
		encryptECB(body, body, cipher)
		return body
	}
}

func cutAndPasteECBOracle() (enc OracleFunc, isAdmin func([]byte) bool) {
	cipher, _ := aes.NewCipher(randomAESkey())

	return func(in []byte) []byte {
			body := pkcs7Padding(in, cipher.BlockSize())
			encryptECB(body, body, cipher)
			return body
		}, func(in []byte) bool {
			body := make([]byte, len(in))
			copy(body, in)
			decryptECB(body, body, cipher)

			values, err := url.ParseQuery(string(body))
			if err != nil {
				return false
			}
			return values.Get("role") == "admin"
		}
}

func randomPrefixSecretECBOracle(secret []byte) OracleFunc {
	cipher, _ := aes.NewCipher(randomAESkey())

	prefix := make([]byte, rand.Intn(32)+10)
	crand.Read(prefix)

	return func(in []byte) []byte {
		body := pkcs7Padding(append(append(prefix, in...), secret...), cipher.BlockSize())
		encryptECB(body, body, cipher)
		return body
	}
}

func cbcBitFlipOracle() (enc OracleFunc, isAdmin func([]byte) bool) {
	cipher, _ := aes.NewCipher(randomAESkey())
	iv := make([]byte, 16)
	crand.Read(iv)

	const (
		prefix = "comment1=cooking%20MCs;userdata="
		suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	)
	return func(in []byte) []byte {
			body := append(append([]byte(prefix), in...), []byte(suffix)...)
			body = bytes.ReplaceAll(body, []byte("&"), []byte("%38"))
			body = bytes.ReplaceAll(body, []byte("="), []byte("%61"))
			body = pkcs7Padding(body, 16)
			encryptCBC(body, body, iv, cipher)
			return body
		}, func(in []byte) bool {
			out := make([]byte, len(in))
			decryptCBC(out, in, iv, cipher)
			stripped, valid := removePkcs7Padding(out)
			if !valid {
				return false
			}
			stripped = bytes.ReplaceAll(stripped, []byte("%38"), []byte("&"))
			stripped = bytes.ReplaceAll(stripped, []byte("%61"), []byte("="))
			return strings.Contains(string(stripped), ";admin=true;")
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
