[![Build Status](https://semaphoreci.com/api/v1/bentranter/passlock/branches/master/badge.svg)](https://semaphoreci.com/bentranter/passlock)
[![GoDoc](https://godoc.org/github.com/bentranter/passlock?status.svg)](https://godoc.org/github.com/bentranter/passlock)

Passlock
---

Slightly more secure than bcrypt alone. Consider this an alternative to "peppering".

Why?
---

1. Bcrypt cuts off anything longer than 72 characters.
2. Some implementations (not Go's however) get freaked out by `NUL` bytes.

> They get freaked out by `NUL` bytes? Who cares?

Some people don't think bcrypt is enough, so they'll "pepper" the user's password by keyed-hashing it before bcrypting it. This is problematic because the hash function can produce `NUL` bytes. This can be solved by base64 (or hex even) encoding the hash output (which is what I do in this lib), but there's still the issue of having to get user's to reset their password if you want to change the key for the hash.

Usage
---

```go
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
```

License
---

MIT. See the license file for more info.

Inspired by [`password_lock`](https://github.com/paragonie/password_lock).

Encryption code taken from [`cryptopasta`](https://github.com/gtank/cryptopasta).
