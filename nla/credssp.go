package nla

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"github.com/jsthtlf/go-ntlm/nla/ntlm"
)

type NegoToken struct {
	Data []byte `asn1:"explicit,tag:0"`
}

type TSRequest struct {
	Version     int         `asn1:"explicit,tag:0"`
	NegoTokens  []NegoToken `asn1:"optional,explicit,tag:1"`
	AuthInfo    []byte      `asn1:"optional,explicit,tag:2"`
	PubKeyAuth  []byte      `asn1:"optional,explicit,tag:3"`
	ErrorCode   int         `asn1:"optional,explicit,tag:4"`
	ClientNonce []byte      `asn1:"optional,explicit,tag:5"`
}

type TSCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

type TSPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

type TSCspDataDetail struct {
	KeySpec       int    `asn1:"explicit,tag:0"`
	CardName      string `asn1:"explicit,tag:1"`
	ReaderName    string `asn1:"explicit,tag:2"`
	ContainerName string `asn1:"explicit,tag:3"`
	CspName       string `asn1:"explicit,tag:4"`
}

type TSSmartCardCreds struct {
	Pin        string            `asn1:"explicit,tag:0"`
	CspData    []TSCspDataDetail `asn1:"explicit,tag:1"`
	UserHint   string            `asn1:"explicit,tag:2"`
	DomainHint string            `asn1:"explicit,tag:3"`
}

func New(version int) *TSRequest {
	request := &TSRequest{
		Version: version,
	}
	return request
}

func (t *TSRequest) Encode(msgs []ntlm.Message, authInfo, pubKeyAuth []byte) {
	if len(msgs) > 0 {
		t.NegoTokens = make([]NegoToken, 0, len(msgs))
	}

	for _, msg := range msgs {
		token := NegoToken{msg.Serialize()}
		t.NegoTokens = append(t.NegoTokens, token)
	}

	if len(authInfo) > 0 {
		t.AuthInfo = authInfo
	}

	if len(pubKeyAuth) > 0 {
		t.PubKeyAuth = pubKeyAuth
	}
}

func EncodeDERTRequest(authInfo, pubKeyAuth []byte, version int, msgsByte ...[]byte) *TSRequest {
	req := &TSRequest{
		Version: version,
	}

	if len(msgsByte) > 0 {
		req.NegoTokens = make([]NegoToken, 0, len(msgsByte))
	}

	for _, msg := range msgsByte {
		token := NegoToken{msg}
		req.NegoTokens = append(req.NegoTokens, token)
	}

	if len(authInfo) > 0 {
		req.AuthInfo = authInfo
	}

	if len(pubKeyAuth) > 0 {
		req.PubKeyAuth = pubKeyAuth
	}

	return req
}

func DecodeDERTRequest(s []byte) (*TSRequest, error) {
	treq := &TSRequest{}
	_, err := asn1.Unmarshal(s, treq)

	if treq.Version < 2 || treq.Version > 6 {
		return nil, errors.New("receive request with unsupported version")
	}
	return treq, err
}
func EncodeDERTCredentials(domain, username, password []byte) ([]byte, error) {
	tpas := TSPasswordCreds{domain, username, password}
	result, err := asn1.Marshal(tpas)
	if err != nil {
		return nil, err
	}
	tcre := TSCredentials{1, result}
	result, err = asn1.Marshal(tcre)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DecodeDERTCredentials(s []byte) (*TSCredentials, error) {
	tcre := &TSCredentials{}
	_, err := asn1.Unmarshal(s, tcre)
	return tcre, err
}

func DecodeDERTPasswordCreds(s []byte) (*TSPasswordCreds, error) {
	tcre := &TSPasswordCreds{}
	_, err := asn1.Unmarshal(s, tcre)
	return tcre, err
}

func (r TSRequest) Serialize() ([]byte, error) {
	return asn1.Marshal(r)
}

func randomBytes(length int) []byte {
	randombytes := make([]byte, length)
	_, err := rand.Read(randombytes)
	if err != nil {
	} // TODO: What to do with err here
	return randombytes
}
