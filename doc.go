/*
Package cloudssh provides an implementation of golang.org/x/crypto/ssh.Signer that uses AWS KMS or Azure KeyVault to perform cryptographic operations

AWS Example:

	kmsSigner, err := NewKmsSigner(kmsKeyId)
	if err != nil {
		log.Fatal(err)
	}

	sshconfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(kmsSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

Azure Example:

	kvSigner, err := NewKvSigner(
		VaultUrl,
		KeyName,
		KeyVersion,
	)
	if err != nil {
		log.Fatal(err)
	}

	sshconfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(kvSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
*/
package cloudssh
