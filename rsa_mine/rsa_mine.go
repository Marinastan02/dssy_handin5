package rsa_mine

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type RSA struct {
	N *big.Int
	E *big.Int
	D *big.Int
}

func KeyGen(k int) (*RSA, error) {
	e := big.NewInt(3)
	one := big.NewInt(1)

	var p, q, n, phi, d *big.Int
	for {
		p, _ = rand.Prime(rand.Reader, k/2)
		q, _ = rand.Prime(rand.Reader, k/2)

		// Ensure gcd(3, p-1) == 1 and gcd(3, q-1) == 1
		if new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(p, one)).Cmp(one) != 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, e, new(big.Int).Sub(q, one)).Cmp(one) != 0 {
			continue
		}

		break
	}

	// n = p * q (modulus)
	n = new(big.Int).Mul(p, q)

	// phi = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	phi = new(big.Int).Mul(pMinus1, qMinus1)

	d = new(big.Int)
	if d.ModInverse(e, phi) == nil {
		return nil, errors.New("failed to calculate modular inverse")
	}

	if n.BitLen() != k {
		return nil, errors.New("modulus does not have the required bit length")
	}

	return &RSA{
		N: n,
		E: e,
		D: d,
	}, nil
}

func (rsa *RSA) Encrypt(plaintext *big.Int) (*big.Int, error) {
	if plaintext.Cmp(rsa.N) >= 0 {
		return nil, errors.New("plaintext too large")
	}

	// ciphertext = plaintext^e mod n
	ciphertext := new(big.Int).Exp(plaintext, rsa.E, rsa.N)
	return ciphertext, nil
}

func (rsa *RSA) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	if ciphertext.Cmp(rsa.N) >= 0 {
		return nil, errors.New("ciphertext too large")
	}

	// plaintext = ciphertext^d mod n
	plaintext := new(big.Int).Exp(ciphertext, rsa.D, rsa.N)
	return plaintext, nil
}

func (rsa *RSA) Sign(message []byte) (*big.Int, error) {
	hash := sha256.Sum256(message)

	hashInt := new(big.Int).SetBytes(hash[:])

	signature := new(big.Int).Exp(hashInt, rsa.D, rsa.N)
	return signature, nil
}

func (rsa *RSA) Verify(message []byte, signature *big.Int) (bool, error) {
	hash := sha256.Sum256(message)

	hashInt := new(big.Int).SetBytes(hash[:])

	verifiedHashInt := new(big.Int).Exp(signature, rsa.E, rsa.N)

	return hashInt.Cmp(verifiedHashInt) == 0, nil
}
