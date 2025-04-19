package cloudssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stormentt/cloudssh/sshutil"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"slices"
)

type KmsSigner struct {
	KeyId     string
	PubKey    ssh.PublicKey
	AwsConfig aws.Config
}

func NewKmsSigner(awsConfig aws.Config, keyId string) (*KmsSigner, error) {
	kmsClient := kms.NewFromConfig(awsConfig)

	resp, err := kmsClient.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	})
	if err != nil {
		return nil, err
	}

	decoded, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, err
	}

	var sshPubKey ssh.PublicKey

	switch decoded.(type) {
	case *rsa.PublicKey:
		if slices.Contains(resp.SigningAlgorithms, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512) {
			sshPubKey = sshutil.New512(decoded.(*rsa.PublicKey))
		} else if slices.Contains(resp.SigningAlgorithms, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256) {
			sshPubKey = sshutil.New256(decoded.(*rsa.PublicKey))
		} else {
			return nil, KmsKeyLacksSupportedAlgorithms{
				KeyId:                     *resp.KeyId,
				KeySigningAlgorithms:      resp.SigningAlgorithms,
				RequiredSigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
			}
		}
	case *ecdsa.PublicKey:
		sshPubKey, err = ssh.NewPublicKey(decoded)
		if err != nil {
			return nil, err
		}
	default:
		return nil, UnsupportedKeyType{string(resp.KeySpec)}
	}

	return &KmsSigner{
		KeyId:     keyId,
		PubKey:    sshPubKey,
		AwsConfig: awsConfig,
	}, nil
}

func (k *KmsSigner) PublicKey() ssh.PublicKey {
	return k.PubKey
}

func (k *KmsSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	var signingAlgorithm types.SigningAlgorithmSpec

	switch k.PubKey.Type() {
	case ssh.KeyAlgoRSASHA256:
		signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	case ssh.KeyAlgoRSASHA512:
		signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
	case ssh.KeyAlgoECDSA256:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha256
	case ssh.KeyAlgoECDSA384:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha384
	case ssh.KeyAlgoECDSA521:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha512

	default:
		return nil, UnsupportedKeyType{k.PubKey.Type()}
	}

	kmsClient := kms.NewFromConfig(k.AwsConfig)
	signature, err := kmsClient.Sign(
		context.Background(),
		&kms.SignInput{
			KeyId:            &k.KeyId,
			Message:          data,
			SigningAlgorithm: signingAlgorithm,
			DryRun:           aws.Bool(false),
			GrantTokens:      nil,
			MessageType:      types.MessageTypeRaw,
		},
	)
	if err != nil {
		return nil, err
	}

	sigBytes := signature.Signature

	if signingAlgorithm == types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 || signingAlgorithm == types.SigningAlgorithmSpecRsassaPkcs1V15Sha512 {
		return &ssh.Signature{
			Format: k.PubKey.Type(),
			Blob:   sigBytes,
			Rest:   nil,
		}, nil
	} else {
		var parsedSig struct{ R, S *big.Int }
		if _, err = asn1.Unmarshal(sigBytes, &parsedSig); err != nil {
			return nil, err
		}

		return &ssh.Signature{
			Format: k.PubKey.Type(),
			Blob:   ssh.Marshal(parsedSig),
		}, nil
	}

}
