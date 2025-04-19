[![Go Reference](https://pkg.go.dev/badge/github.com/stormentt/cloudssh.svg)](https://pkg.go.dev/github.com/stormentt/cloudssh)

# CloudSSH
CloudSSH is a package that provides an [ssh.Signer](https://pkg.go.dev/golang.org/x/crypto/ssh#Signer) implementation for AWS KMS and Azure Keyvault.

# Example Usage
```go
awsConfig, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"))
if err != nil { panic(err) }

kmsSigner, err := cloudssh.NewKmsSigner(awsConfig, "kms-key-id")
if err != nil { panic(err) }

azureCreds, err := azidentity.NewDefaultAzureCredential(nil)
if err != nil { panic(err) }

kvSigner, err := cloudssh.NewKvSigner(azureCreds, "https://your-vault-name.vault.azure.net", "your-key-name", "key-version")
if err != nil { panic(err) }

sshconfig := &ssh.ClientConfig{
    User: "user",
    Auth: []ssh.AuthMethod{
        ssh.PublicKeys(kmsSigner, kvSigner),
    },
    HostKeyCallback: ssh.InsecureIgnoreHostKey(), // please don't actually use InsecureIgnoreHostKey
}

client, err := ssh.Dial("tcp", "example.com:22", sshconfig)
if err != nil { panic(err) }

session, err := client.NewSession()
if err != nil { panic(err) }

output, err := session.CombinedOutput("/usr/bin/whoami")
if err != nil { panic(err) }
fmt.Println(string(output))
```
