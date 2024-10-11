package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestGenerateAndSign(t *testing.T) {
	filename := "test_encrypted_rsa_key.pem"
	password := "strong_password"
	invalidPassword := "wrong_password"
	message := []byte("This is a test message")

	pubKey := Generate(filename, password)
	if pubKey == "" {
		t.Fatal("Failed to generate public key")
	}

	signature := Sign(filename, password, message)
	if len(signature) == 0 {
		t.Fatal("Failed to sign the message with correct password")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected an error when signing with the wrong password, but none occurred")
		}
	}()
	Sign(filename, invalidPassword, message)
}

func TestBruteforceSimulation(t *testing.T) {
	filename := "test_encrypted_rsa_key.pem"
	password := "strong_password"
	message := []byte("Another test message")

	Generate(filename, password)

	invalidPasswords := []string{"123", "password", "abc", "admin", "wrong_password"}
	for _, pw := range invalidPasswords {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected an error when using wrong password: %s", pw)
				}
			}()
			Sign(filename, pw, message)
		}()
	}

	t.Logf("Bruteforce simulation test passed")
}

func TestKeyFileTampering(t *testing.T) {
	filename := "test_encrypted_rsa_key.pem"
	password := "strong_password"
	message := []byte("Final test message")

	Generate(filename, password)

	encryptedKey, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	tamperedKey := append(encryptedKey[:len(encryptedKey)-10], bytes.Repeat([]byte{0}, 10)...)
	err = ioutil.WriteFile(filename, tamperedKey, 0600)
	if err != nil {
		t.Fatalf("Failed to write tampered key file: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected an error when using a tampered key file, but none occurred")
		} else {
			t.Logf("Tampering with the key file correctly caused an error")
		}
	}()
	Sign(filename, password, message)
}
