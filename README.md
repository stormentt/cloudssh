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

client, err := ssh.Dial("tcp", "yourserver.com:22", config)
if err != nil {
	log.Fatal("Failed to dial: ", err)
}
defer client.Close()

// Each ClientConn can support multiple interactive sessions,
// represented by a Session.
session, err := client.NewSession()
if err != nil {
	log.Fatal("Failed to create session: ", err)
}
defer session.Close()

// Once a Session is created, you can execute a single command on
// the remote side using the Run method.
var b bytes.Buffer
session.Stdout = &b
if err := session.Run("/usr/bin/whoami"); err != nil {
	log.Fatal("Failed to run: " + err.Error())
}
fmt.Println(b.String())
```



