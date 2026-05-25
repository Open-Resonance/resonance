
// Manages Argon2id key derivation function  
pub mod password_kdf {
    use argon2::{
        password_hash::rand_core::{OsRng, RngCore},
        Algorithm, Argon2, Params, Version,
    };

    const PASSWORD_KEY_LEN: usize = 32;
    const PASSWORD_SALT_LEN: usize = 16;
    const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
    const ARGON2_ITERATIONS: u32 = 3;
    const ARGON2_PARALLELISM: u32 = 1;

    pub struct PasswordKey {
        key: [u8; PASSWORD_KEY_LEN],
        pub metadata: PasswordKdfMetadata,
    }

    pub struct PasswordKdfMetadata {
        pub salt: [u8; PASSWORD_SALT_LEN],
        pub memory_kib: u32,
        pub iterations: u32,
        pub parallelism: u32,
    }

    impl PasswordKey {
        pub(crate) fn as_bytes(&self) -> &[u8; PASSWORD_KEY_LEN] {
            &self.key
        }
    }

    pub fn create_password_key(password: &str) -> Result<PasswordKey, argon2::Error> {
        let mut salt = [0u8; PASSWORD_SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let key = derive_password_key(
            password,
            &salt,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
        )?;

        Ok(PasswordKey {
            key,
            metadata: PasswordKdfMetadata {
                salt,
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
            },
        })
    }

    pub fn recreate_password_key(
        password: &str,
        metadata: &PasswordKdfMetadata,
    ) -> Result<PasswordKey, argon2::Error> {
        let key = derive_password_key(
            password,
            &metadata.salt,
            metadata.memory_kib,
            metadata.iterations,
            metadata.parallelism,
        )?;

        Ok(PasswordKey {
            key,
            metadata: PasswordKdfMetadata {
                salt: metadata.salt,
                memory_kib: metadata.memory_kib,
                iterations: metadata.iterations,
                parallelism: metadata.parallelism,
            },
        })
    }

    fn derive_password_key(
        password: &str,
        salt: &[u8; PASSWORD_SALT_LEN],
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<[u8; PASSWORD_KEY_LEN], argon2::Error> {
        let mut key = [0u8; PASSWORD_KEY_LEN];
        let params = Params::new(memory_kib, iterations, parallelism, Some(PASSWORD_KEY_LEN))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
        Ok(key)
    }
}

// Manages the creation, wrapping and unwrapping of the vault key
pub mod vault_key {
    use super::password_kdf::PasswordKey;
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        Key, XChaCha20Poly1305, XNonce,
    };
    use std::{error::Error, fmt};

    const VAULT_KEY_LEN: usize = 32;
    const VAULT_KEY_WRAP_NONCE_LEN: usize = 24;

    pub struct VaultKey {
        key: [u8; VAULT_KEY_LEN],
    }

    pub struct WrappedVaultKey {
        pub nonce: [u8; VAULT_KEY_WRAP_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    #[derive(Debug)]
    pub enum VaultKeyError {
        Aead(chacha20poly1305::Error),
        InvalidVaultKeyLength(usize),
    }

    impl VaultKey {
        pub(crate) fn as_bytes(&self) -> &[u8; VAULT_KEY_LEN] {
            &self.key
        }
    }

    pub fn create_vault_key() -> VaultKey {
        let mut key = [0u8; VAULT_KEY_LEN];
        OsRng.fill_bytes(&mut key);

        VaultKey { key }
    }

    pub fn wrap_vault_key(
        vault_key: &VaultKey,
        password_key: &PasswordKey,
    ) -> Result<WrappedVaultKey, VaultKeyError> {
        let mut nonce = [0u8; VAULT_KEY_WRAP_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let cipher = cipher_from_password_key(password_key);
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), vault_key.as_bytes().as_slice())?;

        Ok(WrappedVaultKey { nonce, ciphertext })
    }

    pub fn unwrap_vault_key(
        wrapped_vault_key: &WrappedVaultKey,
        password_key: &PasswordKey,
    ) -> Result<VaultKey, VaultKeyError> {
        let cipher = cipher_from_password_key(password_key);
        let plaintext = cipher.decrypt(
            XNonce::from_slice(&wrapped_vault_key.nonce),
            wrapped_vault_key.ciphertext.as_ref(),
        )?;

        let key: [u8; VAULT_KEY_LEN] = plaintext
            .try_into()
            .map_err(|plaintext: Vec<u8>| VaultKeyError::InvalidVaultKeyLength(plaintext.len()))?;

        Ok(VaultKey { key })
    }

    impl fmt::Display for VaultKeyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                VaultKeyError::Aead(_) => write!(f, "vault key authentication failed"),
                VaultKeyError::InvalidVaultKeyLength(len) => {
                    write!(f, "invalid vault key length: {len}")
                }
            }
        }
    }

    impl Error for VaultKeyError {}

    impl From<chacha20poly1305::Error> for VaultKeyError {
        fn from(err: chacha20poly1305::Error) -> Self {
            Self::Aead(err)
        }
    }

    fn cipher_from_password_key(password_key: &PasswordKey) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(password_key.as_bytes()))
    }
}

// Manages the encryption and decryption of the vault
pub mod vault {
    use super::vault_key::VaultKey;
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        Key, XChaCha20Poly1305, XNonce,
    };

    const VAULT_NONCE_LEN: usize = 24;

    pub struct VaultPlaintext {
        pub data: Vec<u8>,
    }

    pub struct VaultCiphertext {
        pub nonce: [u8; VAULT_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    pub fn encrypt_vault(
        plaintext: &VaultPlaintext,
        vault_key: &VaultKey,
    ) -> Result<VaultCiphertext, chacha20poly1305::Error> {
        let mut nonce = [0u8; VAULT_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let cipher = cipher_from_vault_key(vault_key);
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.data.as_slice())?;

        Ok(VaultCiphertext { nonce, ciphertext })
    }

    pub fn decrypt_vault(
        ciphertext: &VaultCiphertext,
        vault_key: &VaultKey,
    ) -> Result<VaultPlaintext, chacha20poly1305::Error> {
        let cipher = cipher_from_vault_key(vault_key);
        let data = cipher.decrypt(
            XNonce::from_slice(&ciphertext.nonce),
            ciphertext.ciphertext.as_ref(),
        )?;

        Ok(VaultPlaintext { data })
    }

    fn cipher_from_vault_key(vault_key: &VaultKey) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(vault_key.as_bytes()))
    }
}




#[cfg(test)]
mod tests {
    use super::{password_kdf, vault, vault_key};

    #[test]
    fn recreate_password_key_recreates_the_same_key() {
        let created = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");

        let recreated = password_kdf::recreate_password_key(
            "correct horse battery staple",
            &created.metadata,
        )
        .expect("password key should be recreated");

        assert_eq!(created.as_bytes(), recreated.as_bytes());
        assert_eq!(created.metadata.salt, recreated.metadata.salt);
        assert_eq!(created.metadata.memory_kib, recreated.metadata.memory_kib);
        assert_eq!(created.metadata.iterations, recreated.metadata.iterations);
        assert_eq!(created.metadata.parallelism, recreated.metadata.parallelism);
    }

    #[test]
    fn recreate_password_key_changes_with_wrong_password() {
        let created = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");

        let recreated =
            password_kdf::recreate_password_key("wrong horse battery staple", &created.metadata)
                .expect("password key should be recreated");

        assert_ne!(created.as_bytes(), recreated.as_bytes());
        assert_eq!(created.metadata.salt, recreated.metadata.salt);
    }

    #[test]
    fn wrapped_vault_key_unwraps_to_original_vault_key() {
        let password_key = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");
        let vault_key = vault_key::create_vault_key();

        let wrapped = vault_key::wrap_vault_key(&vault_key, &password_key)
            .expect("vault key should wrap");
        let unwrapped = vault_key::unwrap_vault_key(&wrapped, &password_key)
            .expect("vault key should unwrap");

        assert_eq!(vault_key.as_bytes(), unwrapped.as_bytes());
        assert_ne!(wrapped.nonce, [0u8; 24]);
        assert_ne!(wrapped.ciphertext, vault_key.as_bytes().as_slice());
    }

    #[test]
    fn wrapped_vault_key_rejects_wrong_password_key() {
        let password_key = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");
        let wrong_password_key = password_kdf::create_password_key("wrong horse battery staple")
            .expect("password key should be created");
        let vault_key = vault_key::create_vault_key();
        let wrapped = vault_key::wrap_vault_key(&vault_key, &password_key)
            .expect("vault key should wrap");

        let err = match vault_key::unwrap_vault_key(&wrapped, &wrong_password_key) {
            Ok(_) => panic!("wrong password key should fail authentication"),
            Err(err) => err,
        };

        assert!(matches!(err, vault_key::VaultKeyError::Aead(_)));
    }

    #[test]
    fn vault_encrypts_and_decrypts_plaintext() {
        let vault_key = vault_key::create_vault_key();
        let plaintext = vault::VaultPlaintext {
            data: b"master seed and identity metadata eventually go here".to_vec(),
        };

        let ciphertext =
            vault::encrypt_vault(&plaintext, &vault_key).expect("vault should encrypt");
        let decrypted =
            vault::decrypt_vault(&ciphertext, &vault_key).expect("vault should decrypt");

        assert_eq!(decrypted.data, plaintext.data);
        assert_ne!(ciphertext.nonce, [0u8; 24]);
        assert_ne!(ciphertext.ciphertext, plaintext.data);
    }

    #[test]
    fn vault_decryption_rejects_wrong_vault_key() {
        let vault_key = vault_key::create_vault_key();
        let wrong_vault_key = vault_key::create_vault_key();
        let plaintext = vault::VaultPlaintext {
            data: b"vault plaintext".to_vec(),
        };
        let ciphertext =
            vault::encrypt_vault(&plaintext, &vault_key).expect("vault should encrypt");

        let result = vault::decrypt_vault(&ciphertext, &wrong_vault_key);

        assert!(result.is_err());
    }

    #[test]
    fn vault_decryption_rejects_tampered_ciphertext() {
        let vault_key = vault_key::create_vault_key();
        let plaintext = vault::VaultPlaintext {
            data: b"vault plaintext".to_vec(),
        };
        let mut ciphertext =
            vault::encrypt_vault(&plaintext, &vault_key).expect("vault should encrypt");
        ciphertext.ciphertext[0] ^= 1;

        let result = vault::decrypt_vault(&ciphertext, &vault_key);

        assert!(result.is_err());
    }
}
