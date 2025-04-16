# Rust AES-GCM File Encryptor

A simple, secure command-line tool written in Rust for encrypting and decrypting text or binary files using **AES-256-GCM authenticated encryption** with **password-based key derivation (Argon2)**.

---

## Features

- **AES-256-GCM** authenticated encryption  
- **Per-file random salt and nonce**  
- **Argon2 password-based key derivation**  
- Password confirmation during encryption  
- Simple **CLI interface**  
- Works with any file type: text, images, binaries, etc.

---

## Usage

### Install

```bash
cargo build --release
```

The binary will be in `target/release/`.

---

### Encode (Encrypt)

```bash
./aes_encryptor --mode encode --input secret.txt --output secret.enc
```

- Prompts for a password **and confirmation**
- Produces an encrypted file with embedded salt and nonce

---

### Decode (Decrypt)

```bash
./aes_encryptor --mode decode --input secret.enc --output secret.txt
```

- Prompts for the password
- Verifies and decrypts the file back to its original form

---

## How It Works

- Generates a **16-byte random salt** and **12-byte random nonce** per encryption.
- Uses **Argon2** to derive a 256-bit encryption key from the password and salt.
- Encrypts the file content using **AES-256-GCM**.
- Saves the salt, nonce, and ciphertext together in the output file:

  ```
  [16 bytes salt][12 bytes nonce][ciphertext]
  ```

- Decryption reverses this process.

---

## Example

```bash
# Encrypt
./aes_encryptor -m encode -i message.txt -o message.enc

# Decrypt
./aes_encryptor -m decode -i message.enc -o message.txt
```

---

## Run Tests

```bash
cargo test
```

Includes unit tests for:
- Key derivation consistency  
- In-memory encryption/decryption roundtrip  

---

## Dependencies

- [`aes-gcm`](https://crates.io/crates/aes-gcm)
- [`argon2`](https://crates.io/crates/argon2)
- [`rand`](https://crates.io/crates/rand)
- [`clap`](https://crates.io/crates/clap)
- [`rpassword`](https://crates.io/crates/rpassword)

---

## License

MIT © 2025 Mario Krapp
Free to use, modify, and distribute.
