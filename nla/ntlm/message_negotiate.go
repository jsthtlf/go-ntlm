//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4 bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

func ParseNegotiateMessage(body []byte) (*NegotiateMessage, error) {
	nm := new(NegotiateMessage)

	nm.Signature = body[0:8]
	if !bytes.Equal(nm.Signature, []byte("NTLMSSP\x00")) {
		return nil, errors.New("Invalid NTLM message signature")
	}

	nm.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if nm.MessageType != 1 {
		return nil, errors.New("Invalid NTLM message type should be 0x00000001 for negotiate message")
	}

	var err error

	nm.NegotiateFlags = binary.LittleEndian.Uint32(body[12:16])

	nm.DomainNameFields, err = ReadBytePayload(16, body)
	if err != nil {
		return nil, err
	}

	nm.WorkstationFields, err = ReadBytePayload(24, body)
	if err != nil {
		return nil, err
	}

	// Version (8 bytes): A VERSION structure (section 2.2.2.10) that is present only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field. This structure is used for debugging purposes only. In normal protocol messages, it is ignored and does not affect the NTLM message processing.<9>
	if NTLMSSP_NEGOTIATE_VERSION.IsSet(nm.NegotiateFlags) {
		nm.Version, err = ReadVersionStruct(body[32:40])
		if err != nil {
			return nil, err
		}
	}

	nm.Payload = body[40:]

	return nm, nil
}

func (n *NegotiateMessage) Serialize() []byte {
	payloadLen := 0
	if n.DomainNameFields != nil {
		payloadLen += int(n.DomainNameFields.Len)
	}
	if n.WorkstationFields != nil {
		payloadLen += int(n.WorkstationFields.Len)
	}
	messageLen := 8 + 4 + 4 + 8
	payloadOffset := uint32(messageLen)

	messageBytes := make([]byte, 0, messageLen+payloadLen)
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(n.Signature)
	binary.Write(buffer, binary.LittleEndian, n.MessageType)

	binary.Write(buffer, binary.LittleEndian, n.NegotiateFlags)

	if n.DomainNameFields != nil {
		buffer.Write(n.DomainNameFields.Bytes())
		n.DomainNameFields.Offset = payloadOffset
		payloadOffset += uint32(n.DomainNameFields.Len)
	} else {
		buffer.Write(zeroBytes(8))
	}

	if n.WorkstationFields != nil {
		buffer.Write(n.WorkstationFields.Bytes())
		payloadOffset += uint32(n.WorkstationFields.Len)
		n.WorkstationFields.Offset = payloadOffset
	} else {
		buffer.Write(zeroBytes(8))
	}

	if NTLMSSP_NEGOTIATE_VERSION.IsSet(n.NegotiateFlags) {
		buffer.Write(n.Version.Bytes())
	}

	// Write out the payloads
	if n.DomainNameFields != nil {
		buffer.Write(n.DomainNameFields.Payload)
	}
	if n.WorkstationFields != nil {
		buffer.Write(n.WorkstationFields.Payload)
	}

	return buffer.Bytes()
}

func (n *NegotiateMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Negotiate NTLM Message\n")
	buffer.WriteString(fmt.Sprintf("Payload Offset: %d Length: %d\n", 40, len(n.Payload)))

	if n.DomainNameFields != nil {
		if n.DomainNameFields.Len != 0 {
			buffer.WriteString(n.DomainNameFields.String())
			buffer.WriteString("\n")
		}
	}

	if n.WorkstationFields != nil {
		if n.WorkstationFields.Len != 0 {
			buffer.WriteString(n.WorkstationFields.String())
			buffer.WriteString("\n")
		}
	}

	if n.Version != nil {
		buffer.WriteString(fmt.Sprintf("Version: %s\n", n.Version.String()))
	}

	buffer.WriteString(fmt.Sprintf("Flags %d\n", n.NegotiateFlags))
	buffer.WriteString(FlagsToString(n.NegotiateFlags))

	return buffer.String()
}
