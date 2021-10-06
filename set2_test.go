package cryptopals

import (
	"bytes"
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
