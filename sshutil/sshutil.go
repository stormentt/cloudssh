package sshutil

import (
	"crypto/rsa"
	"golang.org/x/crypto/ssh"
	"math/big"
)

// RFC8832SSHPublicKey implements [ssh.PublicKey] with the rsa-sha2-512 and rsa-sha2-256 public key algorithms, as defined in [RFC 8332].
//
// At time of writing, the [golang.org/x/crypto/ssh] library provides a function to convert from [rsa.PublicKey] to [ssh.PublicKey]. Unfortunately, it will hardcode the "key type" of all rsa keys to ssh-rsa.
//
// ssh-rsa uses SHA1 as the signature hash algorithm which is vulnerable to chosen-prefix collisions and is considered cryptographically broken as a result.
//
// ssh-rsa was disabled by default in [OpenSSH 8.8] (2021), so we have to provide our own implementation of ssh.PublicKey to use the correct public key algorithms.
//
// [OpenSSH 8.8]: https://www.openssh.com/txt/release-8.8
// [RFC 8332]: https://datatracker.ietf.org/doc/html/rfc8332
type RFC8832SSHPublicKey struct {
	internal           *rsa.PublicKey
	publicKeyAlgorithm string
}

// New256 creates an [ssh.PublicKey] from an [rsa.PublicKey] with a type of rsa-sha2-256
func New256(pubKey *rsa.PublicKey) *RFC8832SSHPublicKey {
	return &RFC8832SSHPublicKey{
		internal:           pubKey,
		publicKeyAlgorithm: ssh.KeyAlgoRSASHA256,
	}
}

// New512 creates an [ssh.PublicKey] from an [rsa.PublicKey] with a type of rsa-sha2-512
func New512(pubKey *rsa.PublicKey) *RFC8832SSHPublicKey {
	return &RFC8832SSHPublicKey{
		internal:           pubKey,
		publicKeyAlgorithm: ssh.KeyAlgoRSASHA512,
	}
}

// Type returns the public key algorithm, defined in [RFC 8332]
func (r RFC8832SSHPublicKey) Type() string {
	return r.publicKeyAlgorithm
}

// Marshal serializes the RFC8332SSHPublicKey into the ssh wire format, defined in [RFC 4251 section 5]
//
// [RFC 4251 section 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
func (r RFC8832SSHPublicKey) Marshal() []byte {
	// We have to create a bigint because the ssh.Marshal function will encode ints as uint32's, taking up 4 bytes, but RSA keys are supposed to be marshalled as two mpints.
	// Reference RFC 8332 section 3
	e := new(big.Int).SetInt64(int64(r.internal.E))

	wirekey := struct {
		KeyType string
		E       *big.Int
		N       *big.Int
	}{
		ssh.KeyAlgoRSA,
		e,
		r.internal.N,
	}
	return ssh.Marshal(&wirekey)
}
func (r RFC8832SSHPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	sshPubKey, err := ssh.NewPublicKey(r.internal)
	if err != nil {
		return err
	}
	return sshPubKey.Verify(data, sig)
}
