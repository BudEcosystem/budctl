package spec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// encryptedPrivateKeyType is the PEM label of an encrypted PKCS#8 key
// (RFC 7468), the form the Bud chart ships and its services read.
const encryptedPrivateKeyType = "ENCRYPTED PRIVATE KEY"

// pbkdf2Iterations follows OpenSSL 3's default for `pkcs8 -topk8`.
const pbkdf2Iterations = 2048

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// The ASN.1 shapes of RFC 5958 EncryptedPrivateKeyInfo with RFC 8018 PBES2
// parameters.
type encryptedPrivateKeyInfo struct {
	Algorithm     pbes2Algorithm
	EncryptedData []byte
}

type pbes2Algorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbes2Params
}

type pbes2Params struct {
	KeyDerivation pbkdf2Algorithm
	Encryption    cbcAlgorithm
}

type pbkdf2Algorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pbkdf2Params
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	PRF        pkix.AlgorithmIdentifier
}

type cbcAlgorithm struct {
	Algorithm asn1.ObjectIdentifier
	IV        []byte
}

// encryptPKCS8 wraps a PKCS#8 PrivateKeyInfo in an encrypted PKCS#8 PEM block:
// PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC, what `openssl pkcs8 -topk8`
// writes. The standard library can produce only the legacy "Proc-Type"
// encrypted PEM, which RFC 7468 readers refuse.
func encryptPKCS8(der []byte, password string) (string, error) {
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	plain := append(bytes.Clone(der), bytes.Repeat([]byte{byte(pad)}, pad)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)

	info, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pbes2Algorithm{
			Algorithm: oidPBES2,
			Parameters: pbes2Params{
				KeyDerivation: pbkdf2Algorithm{
					Algorithm: oidPBKDF2,
					Parameters: pbkdf2Params{
						Salt:       salt,
						Iterations: pbkdf2Iterations,
						PRF:        pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue},
					},
				},
				Encryption: cbcAlgorithm{Algorithm: oidAES256CBC, IV: iv},
			},
		},
		EncryptedData: encrypted,
	})
	if err != nil {
		return "", fmt.Errorf("marshal encrypted private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: encryptedPrivateKeyType, Bytes: info})), nil
}
