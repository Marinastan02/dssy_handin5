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
