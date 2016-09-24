[![Build Status](https://semaphoreci.com/api/v1/bentranter/passlock/branches/master/badge.svg)](https://semaphoreci.com/bentranter/passlock)
[![GoDoc](https://godoc.org/github.com/bentranter/passlock?status.svg)](https://godoc.org/github.com/bentranter/passlock)

Passlock
---

Slightly more secure than bcrypt alone.

Why?
---

https://github.com/paragonie/password_lock

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

	println("Passwords matched!")
}
```

License
---

MIT. See the license file for more info.

Inspired by [`password_lock`](https://github.com/paragonie/password_lock).

Encryption code taken from [`cryptopasta`](https://github.com/gtank/cryptopasta).

Todo
---

- Add the ability to rotate keys.
