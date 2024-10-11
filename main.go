package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

type Signature []byte

func Generate(filename string, password string) (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)

	err = ioutil.WriteFile(filename, privKeyPem, 0600)
	if err != nil {
		return "", err
	}

	return string(pubKeyPem), nil
}

func Sign(filename string, password string, msg []byte) (Signature, error) {
	privKeyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hashedMsg := sha256.Sum256(msg)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashedMsg[:], nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func main() {
	pubKey, err := Generate("private_key.pem", "password")
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	fmt.Println("Public key:", pubKey)

	signature, err := Sign("private_key.pem", "password", []byte("Hello, world!"))
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	fmt.Println("Signature:", signature)
}

// func main() {

// 	filename := "encrypted_rsa_key.gob"
// 	password := "my_secure_password"

// 	publicKey := Generate(filename, password)
// 	if publicKey == "" {
// 		fmt.Println("Key generation failed")
// 		return
// 	}
// 	fmt.Println("Public Key generated:", publicKey)

// 	k := 1024 // Bit length for modulus
// 	rsaKey, err := rsa_mine.KeyGen(k)
// 	if err != nil {
// 		fmt.Println("Key generation failed:", err)
// 		return
// 	}

// 	fmt.Printf("Generated RSA key with modulus bit length %d\n", rsaKey.N.BitLen())

// 	if rsaKey.N.BitLen() != k {
// 		fmt.Println("Modulus bit length is incorrect")
// 		return
// 	}

// 	fmt.Println("Modulus bit length is correct")

// 	for i := 0; i < 5; i++ {
// 		plaintext, err := randomIntLessThan(rsaKey.N)
// 		if err != nil {
// 			fmt.Println("Failed to generate random plaintext:", err)
// 			return
// 		}

// 		ciphertext, err := rsaKey.Encrypt(plaintext)
// 		if err != nil {
// 			fmt.Println("Encryption failed:", err)
// 			return
// 		}

// 		decrypted, err := rsaKey.Decrypt(ciphertext)
// 		if err != nil {
// 			fmt.Println("Decryption failed:", err)
// 			return
// 		}

// 		if decrypted.Cmp(plaintext) != 0 {
// 			fmt.Printf("Test failed: original (%v) != decrypted (%v)\n", plaintext, decrypted)
// 		} else {
// 			fmt.Printf("Test passed for plaintext: %v\n", plaintext)
// 		}
// 	}
// 	rsaKey, err = rsa_mine.KeyGen(1024)
// 	if err != nil {
// 		fmt.Println("RSA key generation failed:", err)
// 		return
// 	}

// 	err = saveRSAKeyToFile(rsaKey, "rsa_key.gob")
// 	if err != nil {
// 		fmt.Println("Failed to save RSA key to file:", err)
// 		return
// 	}

// 	// rsaKeyFromFile, err := loadRSAKeyFromFile("rsa_key.gob")
// 	// if err != nil {
// 	// 	fmt.Println("Failed to load RSA key from file:", err)
// 	// 	return
// 	// }

// 	// fmt.Println("RSA Key loaded from file successfully.")

// 	aesKey := []byte("mysecretaeskeywith192bit")
// 	plaintext, err := os.ReadFile("rsa_key.gob")
// 	if err != nil {
// 		fmt.Println("Failed to read RSA key file:", err)
// 		return
// 	}

// 	err = aes_mine.EncryptToFile(aesKey, plaintext, "encrypted_rsa_key.gob")
// 	if err != nil {
// 		fmt.Println("Encryption failed:", err)
// 		return
// 	}
// 	fmt.Println("RSA key file encrypted successfully.")

// 	decrypted, err := aes_mine.DecryptFromFile(aesKey, "encrypted_rsa_key.gob")
// 	if err != nil {
// 		fmt.Println("Decryption failed:", err)
// 		return
// 	}

// 	err = os.WriteFile("decrypted_rsa_key.gob", decrypted, 0644)
// 	if err != nil {
// 		fmt.Println("Failed to write decrypted RSA key file:", err)
// 		return
// 	}
// 	fmt.Println("RSA key decrypted and saved successfully.")

// 	decryptedRSAKey, err := loadRSAKeyFromFile("decrypted_rsa_key.gob")
// 	if err != nil {
// 		fmt.Println("Failed to load decrypted RSA key from file:", err)
// 		return
// 	}

// 	ciphertext, err := decryptedRSAKey.Encrypt(big.NewInt(42))
// 	if err != nil {
// 		fmt.Println("Encryption with decrypted RSA key failed:", err)
// 		return
// 	}

// 	plaintextDecrypted, err := decryptedRSAKey.Decrypt(ciphertext)
// 	if err != nil {
// 		fmt.Println("Decryption with decrypted RSA key failed:", err)
// 		return
// 	}

// 	fmt.Printf("Test passed: original plaintext = %v\n", plaintextDecrypted)

// 	// RSA Signature & Verification

// 	message := []byte("This is a test message for signing.")

// 	start := time.Now()
// 	signature, err := Sign("encrypted_rsa_key.gob", "mysecretaeskeywith192bit", message)
// 	signatureBytes := signature.Bytes()                   // Convert signature to byte slice
// 	signatureInt := new(big.Int).SetBytes(signatureBytes) // Pass the byte slice value of the signature
// 	valid, err := rsaKey.Verify(message, signatureInt)    // Verify the signature
// 	if err != nil {
// 		fmt.Println("Verification failed:", err)
// 		return
// 	}
// 	if valid {
// 		fmt.Println("Signature is valid!")
// 	} else {
// 		fmt.Println("Signature is invalid!")
// 	}
// 	fmt.Printf("Verification took %v nanoseconds\n", time.Since(start).Nanoseconds())

// 	// Modify the message and check verification failure
// 	message[0] ^= 1 // Flip a bit in the message
// 	valid, err = rsaKey.Verify(message, signature)
// 	if err != nil {
// 		fmt.Println("Verification failed:", err)
// 		return
// 	}
// 	if valid {
// 		fmt.Println("Signature should be invalid, but it is valid (unexpected).")
// 	} else {
// 		fmt.Println("Signature is invalid after message modification (expected).")
// 	}

// 	// measure times for exercise 6.15
// 	message = make([]byte, 800000)
// 	message[1] = 1
// 	//fmt.Println(message)
// 	s := time.Now()
// 	hash := sha256.Sum256(message)
// 	diff := time.Since(s).Seconds()
// 	fmt.Println(hash)
// 	fmt.Println(diff)
// 	speed := float64(diff) / 800000.0
// 	fmt.Println("Hashing at a speed of of " + strconv.FormatFloat(speed, 'f', -1, 64) + " Bit/sec")

// 	k = 2000 // Bit length for modulus
// 	rsaKey2000, err := rsa_mine.KeyGen(k)
// 	if err != nil {
// 		fmt.Println("Key generation failed:", err)
// 		return
// 	}

// 	hash = sha256.Sum256(message)
// 	hashInt := new(big.Int).SetBytes(hash[:])
// 	starts := time.Now()
// 	signature = new(big.Int).Exp(hashInt, rsaKey2000.D, rsaKey2000.N)
// 	signingTime := time.Since(starts).Seconds()
// 	if err != nil {
// 		fmt.Println("Signing failed:", err)
// 		return
// 	}
// 	fmt.Printf("Signature generated for 2000 bit key: %x\n", signature)
// 	fmt.Printf("Signing took %v nanoseconds\n", time.Since(starts).Nanoseconds())

// 	speed = float64(800000) / signingTime
// 	fmt.Printf("Speed for signing the hash with 2000 bit RSA: %f bits/sec\n", speed)

// 	startm := time.Now()
// 	msgInt := new(big.Int).SetBytes(message)
// 	signature = new(big.Int).Exp(msgInt, rsaKey2000.D, rsaKey2000.N)
// 	timeWholeMessage := time.Since(startm).Seconds()
// 	fmt.Println("----")
// 	//fmt.Println(msgInt)
// 	//fmt.Println(signature)
// 	fmt.Println(timeWholeMessage)
// 	spped2 := float64(800000) / timeWholeMessage

// 	fmt.Printf("Speed for signing the whole message with 2000 bit RSA:: %f bits/sec\n", spped2)

// 	if speed > (float64(800000) / timeWholeMessage) {
// 		fmt.Println("Signing the hash is more efficient.")
// 	} else {
// 		fmt.Println("Signing without hashing is more efficient.")
// 	}

// }
