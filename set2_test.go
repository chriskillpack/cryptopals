package cryptopals

import (
	"bytes"
	"crypto/aes"
	"math/rand"
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
	decryptCBC(plaintext, []byte(cipherdata), iv, cipher)
	if !strings.HasPrefix(string(plaintext), "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell") {
		t.Error("Did not CBC decrypt correctly")
	}
}

// I really struggled with this problem because I had a hard time understanding
// what the detector was meant to do. From the problem statement:
// "Detect the block cipher mode the function is using each time. You should
// end up with a piece of code that, pointed at a block box that might be
// encrypting ECB or CBC, tells you which one is happening."
// I took this to mean "scan individual blocks in the output and determine if
// they are ECB or CBC encrypted". I had to watch FiloSottile's live coding
// stream to see what solution they landed on. I ended up copying them and
// moving on.
func TestChallenge11(t *testing.T) {
	rand.Seed(218) // for repeatable behavior in this test
	in := bytes.Repeat([]byte{111}, 3*16)

	ecb, cbc := 0, 0
	for i := 0; i < 100; i++ {
		out, err := encryptionOracle([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if detectECB(out) {
			ecb++
		} else {
			cbc++
		}
	}

	// This test is brittle, relies on the specific seed and tests against
	// measurements from the first run, which we assume to be correct. But it
	// gives us something.
	if ecb != 27 {
		t.Errorf("Expected 27:73 for ECB:CBC but got %d:%d", ecb, cbc)
	}
}
