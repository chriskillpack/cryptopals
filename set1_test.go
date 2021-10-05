package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestChallenge1(t *testing.T) {
	out, err := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if out != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Error("Got", out)
	}
}

func TestChallenge2(t *testing.T) {
	out := decodeHex(t, "1c0111001f010100061a024b53535009181c")
	out2 := decodeHex(t, "686974207468652062756c6c277320657965")
	c := xor(out, out2)
	if !bytes.Equal(c, decodeHex(t, "746865206b696420646f6e277420706c6179")) {
		t.Error("Got ", string(c))
	}
}

func TestChallenge3(t *testing.T) {
	c := corpusFromFile(t, "testdata/alice_in_wonderland.txt")
	in := decodeHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	var bestScore float64
	var bestCandidate string
	for i := 0; i < 256; i++ {
		candidate := string(singleByteXor(in, byte(i)))
		score := scoreText(candidate, c)
		if score > bestScore {
			bestScore = score
			bestCandidate = candidate
		}
	}
	t.Log(bestCandidate)
}

func TestChallenge4(t *testing.T) {
	c := corpusFromFile(t, "testdata/alice_in_wonderland.txt")

	xors, err := os.Open("testdata/challenge_4.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer xors.Close()

	r := bufio.NewReader(xors)
	var bestCandidate string
	var bestScore float64
	for {
		xor, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		xor = strings.TrimSuffix(xor, "\n")
		data := decodeHex(t, xor)
		s, _, sc := bestSingleXor(data, c)
		if sc > bestScore {
			bestCandidate = s
			bestScore = sc
		}
	}
	t.Logf("%s %.5f\n", bestCandidate, bestScore)
}

func TestChallenge5(t *testing.T) {
	in := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	out := repeatingXor(in, []byte("ICE"))
	expected, err := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a" +
		"282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, expected) {
		t.Errorf("Got %s\n", hex.Dump(expected))
	}
}

func TestChallenge6(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/challenge_6.txt")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		t.Fatal(err)
	}

	// Compute candidate rotating XOR cipher lengths (keysize) using minimal "edit distances"
	type candidate struct {
		editDist float64
		keysize  int
	}

	var results []candidate
	for keysize := 2; keysize <= 40; keysize++ {
		// FiloSottile's idea to *8 is key here so that we have a larger block over which to
		// compute a more accurate Hamming distance. This process does have element of trial
		// and error.
		dist := hammingDistance(cipher[:keysize*8], cipher[keysize*8:keysize*8*2])
		results = append(results, candidate{float64(dist) / float64(keysize), keysize})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].editDist < results[j].editDist
	})
	c := corpusFromFile(t, "testdata/alice_in_wonderland.txt")

	// Using the top result ...
	for cki := 0; cki < 1; cki++ {
		// Cut the cipher text into keysize blocks
		keysize := results[cki].keysize

		// NOTE: All this allocation for building the transpose arrays is unnecessary.
		// They can be constructed directly from cipher slice. But they are here because
		// that's how the code started.

		start, end := 0, keysize
		// How many blocks of len keysize will this be broken into?
		nBlocks := (len(cipher) + keysize - 1) / keysize
		blocks := make([][]byte, nBlocks)
		for b := 0; b < nBlocks; b++ {
			blocks[b] = make([]byte, end-start)
			copy(blocks[b], cipher[start:end])
			start = end
			end += keysize
			if end > len(cipher) {
				end = len(cipher)
			}
		}

		// Now transpose the blocks data so that we have keysize num blocks of
		// nBlocks length
		tblocks := make([][]byte, keysize)
		for b := 0; b < keysize; b++ {
			tblocks[b] = make([]byte, 0, nBlocks)
			for i := 0; i < nBlocks; i++ {
				if b < len(blocks[i]) {
					tblocks[b] = append(tblocks[b], blocks[i][b])
				}
			}
		}

		recoveredKey := make([]byte, keysize)
		for i, tb := range tblocks {
			_, recoveredKey[i], _ = bestSingleXor(tb, c)
		}

		t.Logf("KEY: %#v\n", recoveredKey)
		t.Logf("%s\n", string(repeatingXor(cipher, recoveredKey)))
	}
}

func TestHammingDistance(t *testing.T) {
	distance := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if distance != 37 {
		t.Errorf("Expected 37, got %d", distance)
	}
}

func bestSingleXor(in []byte, corpus map[rune]float64) (text string, xor byte, score float64) {
	var bestScore float64
	var bestCandidate string
	var bestXor byte
	for i := 0; i < 256; i++ {
		candidate := string(singleByteXor(in, byte(i)))
		score := scoreText(candidate, corpus)
		if score > bestScore {
			bestScore = score
			bestXor = byte(i)
			bestCandidate = candidate
		}
	}

	return bestCandidate, bestXor, bestScore
}

func decodeHex(t *testing.T, h string) []byte {
	x, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func corpusFromFile(t *testing.T, file string) map[rune]float64 {
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return buildRuneFreqMap(string(data))
}
