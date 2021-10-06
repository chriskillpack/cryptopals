package cryptopals

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
