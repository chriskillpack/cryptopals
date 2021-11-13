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
		if found, _ := detectECB(out); found {
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
		if found, _ := detectECB(out); found {
			bs = i / 2
			break
		}
	}
	// For this example we know that the cipher blocksize is 16 bytes
	if bs != 16 {
		t.Errorf("Expected blocksize of 16, got %d", bs)
	}

	recovered := recoverSecretFromECB(oracle, len(secret), 0, 0, bs)
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

func TestChallenge14(t *testing.T) {
	secret, err := base64.StdEncoding.DecodeString(challenge12Suffix)
	if err != nil {
		t.Fatal(err)
	}
	oracle := randomPrefixSecretECBOracle([]byte(secret))

	// We know that there is a random byte prefix of unknown length in the
	// ciphertext (p = prefix byte, I = input byte, s = secret byte):
	// pppppppppppppppp|...|pppppppIIIIIIIII|IIIIIsssssssssss
	// Because prefix is random we know that ECB ciphertext blocks are unlikely
	// to repeat. If we pass a large enough buffer of a constant to the oracle
	// we know at some place the ciphertext will start repeating:
	// 00000000  fc 3b 37 9a 2f 36 ed 45  8b 83 ca 6d 13 8c db d8
	// 00000010  b0 fd 38 20 b0 aa f4 ba  3b 85 b8 81 1a 7e 0d 7b
	// 00000020  f9 0d b7 e0 2b c7 0f ad  d6 71 9f 90 03 dd 72 94
	// 00000030  86 d5 01 0d 32 cc 97 88  c6 4d 0f 84 58 d6 1f 36
	// 00000040  e3 98 0e be 91 02 f0 48  8d f3 59 95 90 a3 26 fc
	// 00000050  e3 98 0e be 91 02 f0 48  8d f3 59 95 90 a3 26 fc
	// 00000060  ....
	// 00000420  45 4b cd 58 f1 f6 0a ab  92 91 b3 5f f8 2d 71 5e
	// 00000430  ....
	// The first block where repetition starts, offset 0x40 above, is the first
	// full block beyond the prefix. Using this block we can perform the same
	// bruteforce attack from Challenge 12 to extract the secret, safely away
	// from the prefix.

	// But we need one more piece of information: the prefix length so we know
	// how much padding to add to get to the beginning of that block. This is
	// easy, we encrypt increasing amounts of padding with the oracle until we
	// detect ECB repetition. That requires at least two block sizes of
	// padding.

	bs := 16 // Assume it's 16 byte blocksize for this problem

	// Compute how much padding is needed to get to a block boundary.
	var pad, window int
	var found bool
	for pad = 1; pad < 1024; pad++ {
		rpct := oracle(bytes.Repeat([]byte{192}, pad+bs*2))
		if found, window = detectECB(rpct); found {
			break
		}
	}
	if !found {
		t.Error("Failed to compute padding")
	}
	t.Logf("prefix found, need %d bytes of padding, clean idx is %d", pad, window)

	recovered := recoverSecretFromECB(oracle, len(secret), window, pad, bs)
	if recovered != `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
` {
		t.Errorf("This is not the correct secret %q", recovered)
	}
}
