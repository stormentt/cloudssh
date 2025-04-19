package cloudssh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stormentt/cloudssh/sshutil"
	"golang.org/x/crypto/ssh"
	"hash"
	"io"
	"math/big"
)

type KvSigner struct {
	VaultUrl        string
	KeyName         string
	KeyVersion      string
	PubKey          ssh.PublicKey
	SigAlgo         azkeys.SignatureAlgorithm
	AzureCredential azcore.TokenCredential
}

func NewKvSigner(azureCredential azcore.TokenCredential, vaultUrl, keyName, keyVersion string) (*KvSigner, error) {
	client, err := azkeys.NewClient(vaultUrl, azureCredential, nil)
	if err != nil {
		return nil, err
	}

	kvGetKeyResp, err := client.GetKey(context.Background(), keyName, keyVersion, nil)
	if err != nil {
		return nil, err
	}

	if *kvGetKeyResp.Key.Kty == azkeys.KeyTypeEC || *kvGetKeyResp.Key.Kty == azkeys.KeyTypeECHSM {
		var curve elliptic.Curve
		var sigAlgo azkeys.SignatureAlgorithm

		switch *kvGetKeyResp.Key.Crv {
		case azkeys.CurveNameP256:
			curve = elliptic.P256()
			sigAlgo = azkeys.SignatureAlgorithmES256
		case azkeys.CurveNameP384:
			curve = elliptic.P384()
			sigAlgo = azkeys.SignatureAlgorithmES384
		case azkeys.CurveNameP521:
			curve = elliptic.P521()
			sigAlgo = azkeys.SignatureAlgorithmES512
		default:
			return nil, fmt.Errorf("unsupported key crv %s", *kvGetKeyResp.Key.Crv)
		}

		x := big.NewInt(0)
		x.SetBytes(kvGetKeyResp.Key.X)

		y := big.NewInt(0)
		y.SetBytes(kvGetKeyResp.Key.Y)

		ecPubKey := ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}

		sshPubKey, err := ssh.NewPublicKey(&ecPubKey)
		if err != nil {
			return nil, err
		}

		return &KvSigner{
			VaultUrl:   vaultUrl,
			KeyName:    keyName,
			KeyVersion: keyVersion,
			PubKey:     sshPubKey,
			SigAlgo:    sigAlgo,
		}, nil

	} else if *kvGetKeyResp.Key.Kty == azkeys.KeyTypeRSA || *kvGetKeyResp.Key.Kty == azkeys.KeyTypeRSAHSM {
		n := big.NewInt(0)
		n.SetBytes(kvGetKeyResp.Key.N)

		e := big.NewInt(0)
		e.SetBytes(kvGetKeyResp.Key.E)

		eInt := int(e.Int64())

		rsaPubKey := rsa.PublicKey{
			N: n,
			E: eInt,
		}

		// In azure we just assume it'll support rsa-sha2-512
		sshPubKey := sshutil.New512(&rsaPubKey)
		return &KvSigner{
			VaultUrl:        vaultUrl,
			KeyName:         keyName,
			KeyVersion:      keyVersion,
			PubKey:          sshPubKey,
			SigAlgo:         azkeys.SignatureAlgorithmRS512,
			AzureCredential: azureCredential,
		}, nil

	} else {
		return nil, UnsupportedKeyType{KeyType: string(*kvGetKeyResp.Key.Kty)}
	}

}

// PublicKey returns the associated ssh.PublicKey
func (k *KvSigner) PublicKey() ssh.PublicKey {
	return k.PubKey
}

// Sign returns a signature for the given data.
// This method will hash the message prior to sending it to Key Vault, using the correct digest method for the signing algorithm supported by the key.
func (k *KvSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	client, err := azkeys.NewClient(k.VaultUrl, k.AzureCredential, nil)
	if err != nil {
		return nil, err
	}

	var hasher hash.Hash

	switch k.SigAlgo {
	case azkeys.SignatureAlgorithmES256:
		hasher = sha256.New()
	case azkeys.SignatureAlgorithmES384:
		hasher = sha512.New384()
	case azkeys.SignatureAlgorithmES512:
		hasher = sha512.New()
	case azkeys.SignatureAlgorithmRS256:
		hasher = sha256.New()
	case azkeys.SignatureAlgorithmRS512:
		hasher = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported signature algo: %s", k.SigAlgo)
	}

	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	kvSignResp, err := client.Sign(context.Background(), k.KeyName, k.KeyVersion, azkeys.SignParameters{
		Algorithm: &k.SigAlgo,
		Value:     hashedData,
	}, nil)
	if err != nil {
		return nil, err
	}

	var sigBlob []byte

	switch k.SigAlgo {
	case azkeys.SignatureAlgorithmES256, azkeys.SignatureAlgorithmES384, azkeys.SignatureAlgorithmES512:
		// Reference RFC 5656 section 3.1.2 for how SSH expects ECDSA signatures to be represented.
		// Azure encodes elliptic curve signatures in some weird format. It just slaps the two ints together, each one taking up half the bytes of the response.
		halfLen := len(kvSignResp.Result) / 2
		R := big.NewInt(0)
		S := big.NewInt(0)

		R.SetBytes(kvSignResp.Result[:halfLen])
		S.SetBytes(kvSignResp.Result[halfLen:])

		ecdsaSig := struct {
			R *big.Int
			S *big.Int
		}{
			R: R,
			S: S,
		}

		sigBlob = ssh.Marshal(ecdsaSig)
	case azkeys.SignatureAlgorithmRS256, azkeys.SignatureAlgorithmRS512:
		// RSA signatures are easy :)
		sigBlob = kvSignResp.Result
	default:
		// this should never happen
		return nil, fmt.Errorf("unsupported signature algo: %s", k.SigAlgo)
	}

	return &ssh.Signature{
		Format: k.PubKey.Type(),
		Blob:   sigBlob,
	}, nil
}
