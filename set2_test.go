package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

const challenge12Suffix = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

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

func TestChallenge11(t *testing.T) {
	rand.Seed(218) // for repeatable behavior in this test

	oracle := encryptionOracle()
	in := bytes.Repeat([]byte{111}, 3*16)
	var ecb, cbc int
	for i := 0; i < 100; i++ {
		out := oracle(in)
		if detectECB(out) {
			ecb++
		} else {
			cbc++
		}
	}

	// This test is brittle, relies on the specific seed and tests against
	// measurements from the first run, which we assume to be correct. But it
	// gives us something.
	if ecb != 48 {
		t.Errorf("Expected 48:52 for ECB:CBC but got %d:%d", ecb, cbc)
	}
}

// Builds a 'fragment' dictionary using the encryption oracle to encrypt every
// possible input block of the form:
//   XXXXRRRRRRRRRRR? where X is the constant, R=recovered secret and ? will
//                    take every value from [0,255].
// This function assumes that the length of recovered is one character less than
// the room we are leaving at the end. offset is the slice index of the
// beginning of the bs sized block that the secret character is being extracted
// from.
func fragmentDict(recovered string, oracle func([]byte) []byte, offset, room, bs int) map[string]byte {
	dictionary := make(map[string]byte)
	for i := 0; i <= 255; i++ {
		fragment := bytes.Repeat([]byte{192}, bs-room)
		fragment = append(fragment, []byte(recovered)...)
		fragment = append(fragment, byte(i))
		out := oracle(fragment)
		dictionary[string(out[offset:offset+bs])] = byte(i)
	}

	return dictionary
}

func TestChallenge12(t *testing.T) {
	secret, err := base64.StdEncoding.DecodeString(challenge12Suffix)
	if err != nil {
		t.Fatal(err)
	}

	oracle := consistentECBOracle(secret)

	// Find the blocksize of the cipher. This is achieved by having
	// consistentECB encrypt an input of varying sizes with a single repeating
	// value, e.g. 'A'. The sizes are chosen to be twice cipher blocksizes
	// which is the minimum amount required to detect a repetition with ECB.
	var bs int
	for _, i := range []int{2, 4, 8, 16, 32, 48, 64} {
		dummy := bytes.Repeat([]byte{192}, i)
		out := oracle(dummy)
		if detectECB(out) {
			bs = i / 2
			break
		}
	}
	// For this example we know that the cipher blocksize is 16 bytes
	if bs != 16 {
		t.Errorf("Expected blocksize of 16, got %d", bs)
	}

	// nb is the number of bs sized blocks to cover the length of unknown
	nb := (len(secret) + bs + 1) / bs
	recovered := ""

	// The problem explains how to extract the secret from the first block. To
	// extract the secret from the other blocks we repeat the technique but
	// shift to different blocks of the encrypted output.
	for blk := 0; blk < nb; blk++ {
		window := blk * bs
		for i := 0; i < bs; i++ {
			if window+i == len(secret) {
				break // Have finished iterating over secret
			}

			// Build the dictionary of fingerprints of all final byte
			// possibilities, for the window of the encrypted output currently
			// being attacked.
			dictionary := fragmentDict(recovered, oracle, window, i+1, bs)

			// Encrypt the partial block.
			fragment := bytes.Repeat([]byte{192}, bs-(i+1))
			out := oracle(fragment)

			// Lookup the next byte of recovered from the current window
			// encrypted output.
			b, ok := dictionary[string(out[window:window+bs])]
			if !ok {
				t.Fatalf("Failed lookup for block %d index %d", blk, i)
			}
			recovered += string(b)
		}
	}

	if recovered != `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
` {
		t.Errorf("This is not the correct secret %q", recovered)
	}
}

func TestChallenge13(t *testing.T) {
	encOracle, decOracle := encryptDecryptECBOracle()

	// Another weakness of ECB is that each block is encrypted separately so an
	// attacker can re-arrange or substitute blocks without detection.
	//
	// url.Values.Get("role") returns first value for role parameter.
	//
	// One input to func is AAAA@A.COMadmin which gives us ciphertext block
	// that contains admin&role=user&.
	// email=AAAA@A.COM|admin&role=user&|uid=16
	//                  ^^^^^^^^^^^^^^^^ block 1
	// Another input is an email address that pushes role= to the end of a block
	// email=AAAAAAAAAA|AAAA@A.COM&role=|user
	// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ block 2
	// If we concatenate block 2 onto the end of block 1 then we have ciphertext
	// for an account email=AAAAAAAAAAAAAA@A.COM with an admin role.

	prof, _ := profileFor("AAAA@A.COMadmin")
	block1 := encOracle([]byte(prof))[16:32]
	prof, _ = profileFor("AAAAAAAAAAAAAA@A.COM")
	block2 := encOracle([]byte(prof))[0:32]
	attack := append(block2, block1...)

	// Attacker sets cookie to attack and sends it to web server which decrypts
	// and checks.
	recov := decOracle(attack)
	values, err := url.ParseQuery(string(recov))
	if err != nil {
		t.Fatal(err)
	}
	role := values.Get("role")
	if role != "admin" {
		t.Errorf("Was expecting admin role, got %q", role)
	}
}

func TestProfileFor(t *testing.T) {
	pf, err := profileFor("foo@bar.com")
	if err != nil {
		t.Fatal(err)
	}

	if pf != "email=foo@bar.com&role=user&uid=10" {
		t.Errorf("Expected \"email=foo@bar.com&role=user&uid=10\", got %q", pf)
	}

	san, err := profileFor("foo@bar.com&role=admin")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(san, "bar.com&role") || strings.Contains(san, "role=admin") {
		t.Errorf("Expected %q to have been sanitized", san)
	}
}
