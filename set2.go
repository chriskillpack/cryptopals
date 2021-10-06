package cryptopals

import "crypto/cipher"

func pkcs7Padding(data []byte, blocksize int) []byte {
	padding := blocksize - (len(data) % blocksize)
	if padding > 255 {
		panic("Cannot represent padding amount in a byte")
	}
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(data)+padding; i++ {
		out[i] = byte(padding)
	}
	return out
}

func encryptECB(in, out []byte, cipher cipher.Block) {
	if len(out) != len(in) {
		panic("Unequal length buffers")
	}

	for i := 0; i < len(in); i += cipher.BlockSize() {
		cipher.Encrypt(out[i:], in[i:])
	}
}

// WARNING: This has not been tested yet
// iv = Initialization Vector, the contents are overwritten
func encryptCBC(in, out, iv []byte, cipher cipher.Block) {
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
func decryptCBC(in, out, iv []byte, cipher cipher.Block) {
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
