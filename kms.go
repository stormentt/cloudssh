package cloudssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stormentt/cloudssh/sshutil"
	"golang.org/x/crypto/ssh"
	"hash"
	"io"
	"math/big"
	"slices"
)

// KmsSigner implements [ssh.Signer] using AWS KMS to perform the cryptographic operations
type KmsSigner struct {
	KeyId     string
	PubKey    ssh.PublicKey
	AwsConfig aws.Config
}

// NewKmsSigner takes an aws.Config and KMS Key ID and returns a KmsSigner
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

// PublicKey returns the associated ssh.PublicKey
func (k *KmsSigner) PublicKey() ssh.PublicKey {
	return k.PubKey
}

// Sign returns a signature for the given data.
// This method will hash the message prior to sending it to KMS, using the correct digest method for the signing algorithm supported by the key.
func (k *KmsSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	var signingAlgorithm types.SigningAlgorithmSpec
	var hasher hash.Hash

	switch k.PubKey.Type() {
	case ssh.KeyAlgoRSASHA256:
		signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
		hasher = sha256.New()
	case ssh.KeyAlgoRSASHA512:
		signingAlgorithm = types.SigningAlgorithmSpecRsassaPkcs1V15Sha512
		hasher = sha512.New()
	case ssh.KeyAlgoECDSA256:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha256
		hasher = sha256.New()
	case ssh.KeyAlgoECDSA384:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha384
		hasher = sha512.New384()
	case ssh.KeyAlgoECDSA521:
		signingAlgorithm = types.SigningAlgorithmSpecEcdsaSha512
		hasher = sha512.New()

	default:
		return nil, UnsupportedKeyType{k.PubKey.Type()}
	}

	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	kmsClient := kms.NewFromConfig(k.AwsConfig)
	signature, err := kmsClient.Sign(
		context.Background(),
		&kms.SignInput{
			KeyId:            &k.KeyId,
			Message:          hashedData,
			SigningAlgorithm: signingAlgorithm,
			DryRun:           aws.Bool(false),
			GrantTokens:      nil,
			MessageType:      types.MessageTypeDigest,
		},
	)
	if err != nil {
		return nil, err
	}

	sigBytes := signature.Signature
	var sigBlob []byte

	switch signingAlgorithm {
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		// RSA signatures are easy :)
		sigBlob = signature.Signature
	case types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecEcdsaSha384, types.SigningAlgorithmSpecEcdsaSha512:
		// Reference RFC 5656 section 3.1.2 for how SSH expects ECDSA signatures to be represented.
		// AWS gives us an asn1 encoded object, defined in RFC 3279 section 2.2.3.
		// We have to convert from asn1 to the ssh wire encoding but luckily that's easy
		var parsedSig struct{ R, S *big.Int }
		if _, err = asn1.Unmarshal(sigBytes, &parsedSig); err != nil {
			return nil, err
		}
		sigBlob = ssh.Marshal(parsedSig)
	default:
		// this should be impossible
		return nil, fmt.Errorf("unsupported signing algorithm: %s", signingAlgorithm)
	}

	return &ssh.Signature{
		Format: k.PubKey.Type(),
		Blob:   sigBlob,
	}, nil
}
