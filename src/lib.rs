use aes_gcm::{Aes256Gcm, Nonce, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use std::fs;

pub fn prompt_password_confirmed() -> String {
    let pw1 = prompt_password("Enter password: ").expect("Failed to read password");
    let pw2 = prompt_password("Confirm password: ").expect("Failed to read password");

    if pw1 != pw2 {
        eprintln!("Error: Passwords do not match.");
        std::process::exit(1);
    }
    pw1
}

pub fn prompt_password_once() -> String {
    prompt_password("Enter password: ").expect("Failed to read password")
}

pub fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let config = Argon2::default();
    let mut key_bytes = [0u8; 32];

    config
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .expect("Key derivation failed");

    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

pub fn encode_file(input: &str, output: &str) {
    let password = prompt_password_confirmed();

    let plaintext = fs::read(input).expect("Failed to read input file");

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(&password, &salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    let mut file_data = Vec::new();
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&ciphertext);

    fs::write(output, file_data).expect("Failed to write output file");
    println!("File successfully encoded to {}", output);
}

pub fn decode_file(input: &str, output: &str) {
    let password = prompt_password_once();

    let data = fs::read(input).expect("Failed to read input file");

    if data.len() < 28 {
        eprintln!("File too short to be valid.");
        std::process::exit(1);
    }

    let salt = &data[..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];

    let key = derive_key(&password, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .expect("Decryption failed — wrong password or file corrupted");

    fs::write(output, plaintext).expect("Failed to write output file");
    println!("File successfully decoded to {}", output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_key_derivation_consistency() {
        let password = "test_password";
        let salt = [1u8; 16];
        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);
        assert_eq!(key1, key2, "Derived keys should match for same password and salt");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "roundtrip_password";
        let plaintext = b"Hello, world!";
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption failed");
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).expect("Decryption failed");

        assert_eq!(plaintext.as_ref(), decrypted.as_slice(), "Decrypted text should match original plaintext");
    }
}
