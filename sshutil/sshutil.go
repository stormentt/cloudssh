package sshutil

import (
	"crypto/rsa"
	"golang.org/x/crypto/ssh"
	"math/big"
)

type Ssh2RsaPublicKey struct {
	internal *rsa.PublicKey
	keyType  string
}

func New256(pubKey *rsa.PublicKey) *Ssh2RsaPublicKey {
	return &Ssh2RsaPublicKey{
		internal: pubKey,
		keyType:  ssh.KeyAlgoRSASHA256,
	}
}

func New512(pubKey *rsa.PublicKey) *Ssh2RsaPublicKey {
	return &Ssh2RsaPublicKey{
		internal: pubKey,
		keyType:  ssh.KeyAlgoRSASHA512,
	}
}

func (r Ssh2RsaPublicKey) Type() string {
	return r.keyType
}

func (r Ssh2RsaPublicKey) Marshal() []byte {
	e := new(big.Int).SetInt64(int64(r.internal.E))

	wirekey := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{
		r.keyType,
		e,
		r.internal.N,
	}
	return ssh.Marshal(&wirekey)
}
func (r Ssh2RsaPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	sshPubKey, err := ssh.NewPublicKey(r.internal)
	if err != nil {
		return err
	}
	return sshPubKey.Verify(data, sig)
}
