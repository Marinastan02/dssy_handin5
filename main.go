package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"main/aes_mine"
	"main/rsa_mine"
	"math/big"
	"os"
	"strconv"
	"time"
)

func saveRSAKeyToFile(rsaKey *rsa_mine.RSA, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(rsaKey)
	return err
}

func loadRSAKeyFromFile(filename string) (*rsa_mine.RSA, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rsaKey rsa_mine.RSA
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&rsaKey)
	return &rsaKey, err
}

func Generate(filename string, password string) string {
	// Generate RSA key pair
	k := 1024 // Bit length for modulus
	rsaKey, err := rsa_mine.KeyGen(k)
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
		return ""
	}

	//Derive AES key from password
	passwordHash := sha256.Sum256([]byte(password))
	aesKey := passwordHash[:16] // Take first 16 bytes for AES key

	// Extract private key bytes
	rsaKeyData := rsaKey.D.Bytes()

	// Encrypt the private key with AES
	err = aes_mine.EncryptToFile(aesKey, rsaKeyData, filename)
	if err != nil {
		fmt.Println("Error encrypting RSA key:", err)
		return ""
	}

	// Return the public key as a string
	publicKey := fmt.Sprintf("N: %s, E: %s", rsaKey.N.String(), rsaKey.E.String())
	return publicKey
}

func Sign(filename string, password string, msg []byte) []byte {
	// Derive AES key from password
	passwordHash := sha256.Sum256([]byte(password))
	aesKey := passwordHash[:16] // First 16 bytes for AES key

	// Decrypt the private RSA key from the file
	rsaKeyData, err := aes_mine.DecryptFromFile(aesKey, filename)
	if err != nil {
		fmt.Println("Error decrypting RSA key: ", err)
		return nil
	}

	// Reconstruct RSA private key from decrypted data
	var rsaKey rsa_mine.RSA
	rsaKey.D = new(big.Int).SetBytes(rsaKeyData)

	// Convertibg E from *big.Int to int
	publicExponent := int(rsaKey.E.Int64())

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaKey.N,
			E: publicExponent,
		},
		D: rsaKey.D,
	}

	// Hashing the message
	msgHash := sha256.Sum256(msg)

	// Signing the message using PKCS#1 v1.5 padding
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, msgHash[:])
	if err != nil {
		fmt.Println("Error signing message: ", err)
		return nil
	}

	// signature is of type []byte
	return signature
}

func randomIntLessThan(n *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, n)
}

func main() {
	filename := "encrypted_rsa_key.gob"
	password := "my_secure_password"

	publicKey := Generate(filename, password)
	if publicKey == "" {
		fmt.Println("Key generation failed")
		return
	}
	fmt.Println("Public Key generated:", publicKey)

	k := 1024 // Bit length for modulus
	rsaKey, err := rsa_mine.KeyGen(k)
	if err != nil {
		fmt.Println("Key generation failed:", err)
		return
	}

	fmt.Printf("Generated RSA key with modulus bit length %d\n", rsaKey.N.BitLen())

	if rsaKey.N.BitLen() != k {
		fmt.Println("Modulus bit length is incorrect")
		return
	}

	fmt.Println("Modulus bit length is correct")

	for i := 0; i < 5; i++ {
		plaintext, err := randomIntLessThan(rsaKey.N)
		if err != nil {
			fmt.Println("Failed to generate random plaintext:", err)
			return
		}

		ciphertext, err := rsaKey.Encrypt(plaintext)
		if err != nil {
			fmt.Println("Encryption failed:", err)
			return
		}

		decrypted, err := rsaKey.Decrypt(ciphertext)
		if err != nil {
			fmt.Println("Decryption failed:", err)
			return
		}

		if decrypted.Cmp(plaintext) != 0 {
			fmt.Printf("Test failed: original (%v) != decrypted (%v)\n", plaintext, decrypted)
		} else {
			fmt.Printf("Test passed for plaintext: %v\n", plaintext)
		}
	}
	rsaKey, err = rsa_mine.KeyGen(1024)
	if err != nil {
		fmt.Println("RSA key generation failed:", err)
		return
	}

	err = saveRSAKeyToFile(rsaKey, "rsa_key.gob")
	if err != nil {
		fmt.Println("Failed to save RSA key to file:", err)
		return
	}

	// rsaKeyFromFile, err := loadRSAKeyFromFile("rsa_key.gob")
	// if err != nil {
	// 	fmt.Println("Failed to load RSA key from file:", err)
	// 	return
	// }

	// fmt.Println("RSA Key loaded from file successfully.")

	aesKey := []byte("mysecretaeskeywith192bit")
	plaintext, err := os.ReadFile("rsa_key.gob")
	if err != nil {
		fmt.Println("Failed to read RSA key file:", err)
		return
	}

	err = aes_mine.EncryptToFile(aesKey, plaintext, "encrypted_rsa_key.gob")
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}
	fmt.Println("RSA key file encrypted successfully.")

	decrypted, err := aes_mine.DecryptFromFile(aesKey, "encrypted_rsa_key.gob")
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	err = os.WriteFile("decrypted_rsa_key.gob", decrypted, 0644)
	if err != nil {
		fmt.Println("Failed to write decrypted RSA key file:", err)
		return
	}
	fmt.Println("RSA key decrypted and saved successfully.")

	decryptedRSAKey, err := loadRSAKeyFromFile("decrypted_rsa_key.gob")
	if err != nil {
		fmt.Println("Failed to load decrypted RSA key from file:", err)
		return
	}

	ciphertext, err := decryptedRSAKey.Encrypt(big.NewInt(42))
	if err != nil {
		fmt.Println("Encryption with decrypted RSA key failed:", err)
		return
	}

	plaintextDecrypted, err := decryptedRSAKey.Decrypt(ciphertext)
	if err != nil {
		fmt.Println("Decryption with decrypted RSA key failed:", err)
		return
	}

	fmt.Printf("Test passed: original plaintext = %v\n", plaintextDecrypted)

	// RSA Signature & Verification

	message := []byte("This is a test message for signing.")

	start := time.Now()
	signature, err := rsaKey.Sign(message)
	if err != nil {
		fmt.Println("Signing failed:", err)
		return
	}
	fmt.Printf("Signature generated: %x\n", signature)
	fmt.Printf("Signing took %v nanoseconds\n", time.Since(start).Nanoseconds())

	start = time.Now()
	valid, err := rsaKey.Verify(message, signature)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}
	if valid {
		fmt.Println("Signature is valid!")
	} else {
		fmt.Println("Signature is invalid!")
	}
	fmt.Printf("Verification took %v nanoseconds\n", time.Since(start).Nanoseconds())

	// Modify the message and check verification failure
	message[0] ^= 1 // Flip a bit in the message
	valid, err = rsaKey.Verify(message, signature)
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}
	if valid {
		fmt.Println("Signature should be invalid, but it is valid (unexpected).")
	} else {
		fmt.Println("Signature is invalid after message modification (expected).")
	}

	// measure times for exercise 6.15
	message = make([]byte, 800000)
	message[1] = 1
	//fmt.Println(message)
	s := time.Now()
	hash := sha256.Sum256(message)
	diff := time.Since(s).Seconds()
	fmt.Println(hash)
	fmt.Println(diff)
	speed := float64(diff) / 800000.0
	fmt.Println("Hashing at a speed of of " + strconv.FormatFloat(speed, 'f', -1, 64) + " Bit/sec")

	k = 2000 // Bit length for modulus
	rsaKey2000, err := rsa_mine.KeyGen(k)
	if err != nil {
		fmt.Println("Key generation failed:", err)
		return
	}

	hash = sha256.Sum256(message)
	hashInt := new(big.Int).SetBytes(hash[:])
	starts := time.Now()
	signature = new(big.Int).Exp(hashInt, rsaKey2000.D, rsaKey2000.N)
	signingTime := time.Since(starts).Seconds()
	if err != nil {
		fmt.Println("Signing failed:", err)
		return
	}
	fmt.Printf("Signature generated for 2000 bit key: %x\n", signature)
	fmt.Printf("Signing took %v nanoseconds\n", time.Since(starts).Nanoseconds())

	speed = float64(800000) / signingTime
	fmt.Printf("Speed for signing the hash with 2000 bit RSA: %f bits/sec\n", speed)

	startm := time.Now()
	msgInt := new(big.Int).SetBytes(message)
	signature = new(big.Int).Exp(msgInt, rsaKey2000.D, rsaKey2000.N)
	timeWholeMessage := time.Since(startm).Seconds()
	fmt.Println("----")
	//fmt.Println(msgInt)
	//fmt.Println(signature)
	fmt.Println(timeWholeMessage)
	spped2 := float64(800000) / timeWholeMessage

	fmt.Printf("Speed for signing the whole message with 2000 bit RSA:: %f bits/sec\n", spped2)

	if speed > (float64(800000) / timeWholeMessage) {
		fmt.Println("Signing the hash is more efficient.")
	} else {
		fmt.Println("Signing without hashing is more efficient.")
	}
}
