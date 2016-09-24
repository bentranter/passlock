package main

import "github.com/bentranter/passlock"

func main() {
	// Your plaintext password
	password := []byte("password")

	// Get a key
	key := passlock.NewEncryptionKey()

	// Store the password
	encryptedPassword, err := passlock.GenerateFromPassword(password, passlock.DefaultCost, key)
	if err != nil {
		println(err)
	}

	// Retrieve the password
	err = passlock.CompareHashAndPassword(encryptedPassword, password, key)
	if err != nil {
		println(err)
		return
	}

	println("Passwords matched!")
}
