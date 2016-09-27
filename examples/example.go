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

	// We're going to rotate keys -- let's start by making a new key
	newKey := passlock.NewEncryptionKey()

	// Rotate the keys
	newEncryptedPassword, err := passlock.RotateKey(key, newKey, encryptedPassword)
	if err != nil {
		println(err)
		return
	}

	// See if that password matches with the new key
	err = passlock.CompareHashAndPassword(newEncryptedPassword, password, newKey)
	if err != nil {
		println(err)
		return
	}

	println("Passwords matched!")
	// Output: Passwords matched!
}
