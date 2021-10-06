package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math/bits"
	"unicode/utf8"
)

func hexToBase64(input string) (string, error) {
	b, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Unequal length buffers")
	}
	x := make([]byte, len(a))
	for i := range a {
		x[i] = a[i] ^ b[i]
	}
	return x
}

func singleByteXor(a []byte, b byte) []byte {
	x := make([]byte, len(a))
	for i := range a {
		x[i] = a[i] ^ b
	}
	return x
}

func repeatingXor(in []byte, key []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ key[i%len(key)]
	}
	return out
}

// Returns a map of rune -> rune frequency in input
func buildRuneFreqMap(in string) map[rune]float64 {
	ch := utf8.RuneCountInString(in)
	m := make(map[rune]float64)
	for _, r := range in {
		m[r]++
	}
	for k, v := range m {
		m[k] = v / float64(ch)
	}
	return m
}

// Scores the input according to the corpus. Higher return values equate to
// being "closer to English" by a very course measure.
func scoreText(text string, corpus map[rune]float64) float64 {
	var score float64
	for _, r := range text {
		score += corpus[r]
	}
	return score
}

// Compute the Hamming Distance between two byte arrays.
// Panics if the byte arrays are unequal length
func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("Unequal length inputs")
	}
	distance := 0
	for i := range a {
		distance += bits.OnesCount8(uint8(a[i] ^ b[i]))
	}

	return distance
}

func decryptECB(in, out []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}

	for i := 0; i < len(in); i += cipher.BlockSize() {
		cipher.Decrypt(out[i:], in[i:])
	}
}
