# as-dss-assignment2

## exercise 6.1

see pdf

## exercise 5.11

see in the code. To run, navigate in to uppermost directory and run `go run ./`


## exercise 6.15

see in code

1. see in code and terminal printout

2. 0.0000000035371250000000002 Bit/sec (see main.go)

3. it took 8908100 nanoseconds to sign the hash value with 2000 bit rsa key (see main.go)

4. Signing on the hash takes shorter than signing the whole message, as the hash is shorter. So hashing makes signing more efficient. (see main.go)


## exercise 9.11

Question 2: Describe clearly what measure have been taken.

The Answer: 
    In this solution, we implemented several measures that could make it quite difficult for an attacker to bruteforce the password. The private key is encrypted using AES, with a key derived from the password through PBKDF2. To slow down password guessing, we have set PBKDF2 to use 500,000 iterations, making each attempt computationally expensive. What is more, we are using a 
    strong hash function, SHA-512, and a random salt to ensure that even if the same password is used elsewhere, the resulting encrypted key is unique.


Question 3: Explain why the system was designed the way it was and, in particular, argue why the system achieves the desired security properties.

The Answer:
    The system was built to make it very challenging for anyone to decrypt the RSA private key without the correct password. By using PBKDF2 with many iterations, each password guess takes more time, making brute force attempts inefficient. A random salt ensures that even if two users have the same password, their encrypted keys will be different. AES encryption is then used to securely protect the private key. Overall, these elements work together to strengthen the system against attacks and protect the key’s confidentiality.

Question 4: Test the system and describe how it was tested.

The Answer:
    TestGenerate - This function is testing the Generate function which generates a public and secret key, encrypts the private key, and saves it to a file. The test checks if the Generate function returns a non-empty string (which should be the public key). If the returned string is empty, the test fails with an error message "Failed to generate public key".
    TestSign - This function is testing the Sign function which reads the encrypted private key, decrypts it, and signs a message. The test checks if the Sign function returns a non-empty Signature. If the returned Signature is empty, the test fails with an error message "Failed to generate signature".

Question 5: Describe how your TA can run the system and how to run the test.

The Answer:
    Since test functions are in the main.go as well, the code is run by typing 'go run main.go' in the terminal.







