[![Go Reference](https://pkg.go.dev/badge/github.com/stormentt/cloudssh.svg)](https://pkg.go.dev/github.com/stormentt/cloudssh)

# CloudSSH
CloudSSH is a package that provides an [ssh.Signer](https://pkg.go.dev/golang.org/x/crypto/ssh#Signer) implementation for AWS KMS and Azure Keyvault.

# Example Usage
```go
kmsSigner, err := NewKmsSigner(kmsKeyId)
if err != nil {
	log.Fatal(err)
}

kvSigner, err := NewKvSigner(
	vaultUrl,
	keyName,
	keyVersion,
)
if err != nil {
	log.Fatal(err)
}

sshconfig := &ssh.ClientConfig{
	User: "user",
	Auth: []ssh.AuthMethod{
		ssh.PublicKeys(kmsSigner, kvSigner),
	},
	HostKeyCallback: ssh.InsecureIgnoreHostKey(),
}
```



