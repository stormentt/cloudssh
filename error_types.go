package cloudssh

import "fmt"

type UnsupportedKeyType struct {
	KeyType string
}

func (r UnsupportedKeyType) Error() string {
	return fmt.Sprintf("unsupported key type: %s", r.KeyType)
}
