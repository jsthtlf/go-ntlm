# NTLM Implementation for Go

This is a native implementation of NTLM for Go that was implemented using the Microsoft MS-NLMP documentation available at http://msdn.microsoft.com/en-us/library/cc236621.aspx.
The library is currently in use and has been tested with connectionless NTLMv1 and v2 with and without extended session security.

## Sample Usage as NTLM Client

```go
import "github.com/jsthtlf/go-ntlm"

session, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")

negotiate := session.GenerateNegotiateMessage()

<send negotiate to server>

challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
session.ProcessChallengeMessage(challenge)

authenticate := session.GenerateAuthenticateMessage()

<send authenticate message to server>
```

## Sample Usage as NTLM Server

```go
session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")

challenge := session.GenerateChallengeMessage()

<send challenge to client>

<receive authentication bytes>

auth, err := ntlm.ParseAuthenticateMessage(authenticateBytes)
session.ProcessAuthenticateMessage(auth)
```

## Generating a message with MAC

Once a session is created you can generate the Mac for a message using:

```go
message := "this is some message to sign"
encryptedMessageWithMac := session.GssEncrypt([]byte(message))
```

## Validate a message with MAC

Once a session is created you can validate the Mac for a received message using:

```go
message := []byte{0x00, 0x00} // this is some message with sign in bytes
decryptedMessage := session.GssDecrypt(message)
```

## License
Copyright Thomson Reuters Global Resources 2013
Apache License