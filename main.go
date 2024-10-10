package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"main/aes_mine"
	"main/rsa_mine"
	"math/big"
	"os"
	"strconv"
	"time"
)

type Signature []byte

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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Convert the rsa.PrivateKey to PEM format
	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)

	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privASN1,
	})

	// Encrypt the PEM data
	encryptedPEM, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privBytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		log.Fatal(err)
	}

	// Save the encrypted PEM data to a file
	err = ioutil.WriteFile(filename, pem.EncodeToMemory(encryptedPEM), 0600)
	if err != nil {
		log.Fatal(err)
	}

	// Return the public key
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes)
}

func Sign(filename string, password string, msg []byte) (*big.Int, error) {
	// Read the encrypted PEM data from the file
	encryptedPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the PEM data
	block, _ := pem.Decode(encryptedPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	privBytes, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		log.Fatal(err)
	}

	// Parse the decrypted PEM data to an rsa.PrivateKey
	privateKey, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Create an instance of your custom RSA type
	rsaKey := &rsa_mine.RSA{
		N: privateKey.N,
		E: big.NewInt(int64(privateKey.E)),
		D: privateKey.D,
	}

	// Sign the message using your custom Sign method
	signature, err := rsaKey.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	return signature, nil
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
	signature, err := Sign("encrypted_rsa_key.gob", "mysecretaeskeywith192bit", message)
	signatureBytes := signature.Bytes()                   // Convert signature to byte slice
	signatureInt := new(big.Int).SetBytes(signatureBytes) // Pass the byte slice value of the signature
	valid, err := rsaKey.Verify(message, signatureInt)    // Verify the signature
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
