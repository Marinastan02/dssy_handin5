package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// Signature is a type alias for the signature bytes
type Signature []byte

// deriveKey generates a key from the password using PBKDF2

func deriveKey(password string, salt []byte) []byte {
	// Use 500,000 iterations
	return pbkdf2.Key([]byte(password), salt, 500000, 32, sha512.New)
}

// encryptPrivateKey encrypts the private key using AES with the password
func encryptPrivateKey(privKeyPem []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(privKeyPem))
	stream.XORKeyStream(ciphertext, privKeyPem)

	// Prepend salt and IV to the ciphertext
	return append(append(salt, iv...), ciphertext...), nil
}

// decryptPrivateKey decrypts the private key using AES with the password
func decryptPrivateKey(encryptedPrivKey []byte, password string) ([]byte, error) {
	if len(encryptedPrivKey) < 32 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt := encryptedPrivKey[:16]
	iv := encryptedPrivKey[16:32]
	ciphertext := encryptedPrivKey[32:]

	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Generate generates a public and secret key, encrypts the private key, and saves it to a file
func Generate(filename string, password string) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Error marshalling public key: %v", err)
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	encryptedPrivKey, err := encryptPrivateKey(privKeyPem, password)
	if err != nil {
		log.Fatalf("Error encrypting private key: %v", err)
	}

	err = ioutil.WriteFile(filename, encryptedPrivKey, 0600)
	if err != nil {
		log.Fatalf("Error writing private key to file: %v", err)
	}

	return string(pubKeyPem)
}

// Sign reads the encrypted private key, decrypts it, and signs the message
func Sign(filename string, password string, msg []byte) Signature {
	encryptedPrivKey, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading private key file: %v", err)
	}

	privKeyPem, err := decryptPrivateKey(encryptedPrivKey, password)
	if err != nil {
		log.Fatalf("Error decrypting private key: %v", err)
	}

	block, _ := pem.Decode(privKeyPem)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalf("Failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}

	hashed := sha256.Sum256(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}

	return Signature(signature)
}

func TestGenerate(t *testing.T) {
	password := "your_password"
	pubKey := Generate("encrypted_rsa_key.pem", password)

	if pubKey == "" {
		t.Errorf("Failed to generate public key")
	}
}

func TestSign(t *testing.T) {
	password := "your_password"
	msg := []byte("Hello, world!")
	sig := Sign("encrypted_rsa_key.pem", password, msg)

	if len(sig) == 0 {
		t.Errorf("Failed to generate signature")
	}
}

func TestSign2(t *testing.T) {
	password := "your_password_wrong"
	msg := []byte("Hello, world!")
	sig := Sign("encrypted_rsa_key.pem", password, msg)

	if len(sig) == 0 {
		t.Errorf("Failed to generate signature")
	}
}

func main() {
	// Example usage
	pubKey := Generate("encrypted_rsa_key.pem", "your_password")
	fmt.Println("Public Key:", pubKey)

	msg := []byte("Hello, world!")
	sig := Sign("encrypted_rsa_key.pem", "your_password", msg)
	fmt.Printf("Signature: %x\n", sig)
	// Manually running tests
	TestGenerate(&testing.T{})
	TestSign(&testing.T{})
	TestSign2(&testing.T{})
}
