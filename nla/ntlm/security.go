package ntlm

import (
	"bytes"
	rc4P "crypto/rc4"
)

type NTLMv2Security struct {
	EncryptRC4 *rc4P.Cipher
	DecryptRC4 *rc4P.Cipher
	SigningKey []byte
	VerifyKey  []byte
	SeqNum     uint32
}

func (n *NTLMv2Security) GssEncrypt(s []byte) []byte {
	p := make([]byte, len(s))
	n.EncryptRC4.XORKeyStream(p, s)
	b := &bytes.Buffer{}

	//signature
	writeUInt32LE(n.SeqNum, b)
	writeBytes(s, b)
	s1 := hmac_MD5(n.SigningKey, b.Bytes())[:8]
	checksum := make([]byte, 8)
	n.EncryptRC4.XORKeyStream(checksum, s1)
	b.Reset()
	writeUInt32LE(0x00000001, b)
	writeBytes(checksum, b)
	writeUInt32LE(n.SeqNum, b)

	writeBytes(p, b)

	n.SeqNum++

	return b.Bytes()
}
func (n *NTLMv2Security) GssDecrypt(s []byte) []byte {
	r := bytes.NewReader(s)
	readUInt32LE(r) //version
	checksum, _ := readBytes(8, r)
	seqNum, _ := readUInt32LE(r)
	data, _ := readBytes(r.Len(), r)

	p := make([]byte, len(data))
	n.DecryptRC4.XORKeyStream(p, data)

	check := make([]byte, len(checksum))
	n.DecryptRC4.XORKeyStream(check, checksum)

	b := &bytes.Buffer{}
	writeUInt32LE(seqNum, b)
	writeBytes(p, b)
	verify := hmac_MD5(n.VerifyKey, b.Bytes())[:8]
	if string(verify) != string(check) {
		return nil
	}
	return p
}
