package cryptopals

import (
	"bytes"
	"crypto/aes"
	"strings"
	"testing"
)

func TestChallenge9(t *testing.T) {
	out := pkcs7Padding([]byte("YELLOW SUBMARINE"), 20)
	if len(out) != 20 {
		t.Errorf("Expected length 20, got %d", len(out))
	}
	if !bytes.Equal(out, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) {
		t.Errorf("Unexpected output %#v", out)
	}
}

func TestChallenge10(t *testing.T) {
	cipherdata := decodeBase64File(t, "testdata/challenge_10.txt")
	cipher, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, len(cipherdata))
	iv := make([]byte, cipher.BlockSize())
	decryptCBC([]byte(cipherdata), plaintext, iv, cipher)
	if !strings.HasPrefix(string(plaintext), "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell") {
		t.Error("Did not CBC decrypt correctly")
	}
}
