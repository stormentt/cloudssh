package cloudssh

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type UnsupportedKeyType struct {
	KeyType string
}

func (r UnsupportedKeyType) Error() string {
	return fmt.Sprintf("unsupported key type: %s", r.KeyType)
}

type KmsKeyLacksSupportedAlgorithms struct {
	KeyId                     string
	KeySigningAlgorithms      []types.SigningAlgorithmSpec
	RequiredSigningAlgorithms []types.SigningAlgorithmSpec
}

func (r KmsKeyLacksSupportedAlgorithms) Error() string {
	return fmt.Sprintf(
		"KMS Keypair %s does not support required algorithms. Required: %s; supported: %s",
		r.KeyId,
		r.KeySigningAlgorithms,
		r.RequiredSigningAlgorithms,
	)
}
