// Manages Argon2id key derivation function
pub mod password_kdf {
    use argon2::{
        Algorithm, Argon2, Params, Version,
        password_hash::rand_core::{OsRng, RngCore},
    };
    use serde::{Deserialize, Serialize};

    const PASSWORD_KEY_LEN: usize = 32;
    const PASSWORD_SALT_LEN: usize = 16;
    const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
    const ARGON2_ITERATIONS: u32 = 3;
    const ARGON2_PARALLELISM: u32 = 1;

    pub struct PasswordKey {
        key: [u8; PASSWORD_KEY_LEN],
        pub metadata: PasswordKdfMetadata,
    }

    #[derive(Deserialize, Serialize)]
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
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    use serde::{Deserialize, Serialize};
    use std::{error::Error, fmt};

    const VAULT_KEY_LEN: usize = 32;
    const VAULT_KEY_WRAP_NONCE_LEN: usize = 24;

    pub struct VaultKey {
        key: [u8; VAULT_KEY_LEN],
    }

    #[derive(Deserialize, Serialize)]
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
        let ciphertext =
            cipher.encrypt(XNonce::from_slice(&nonce), vault_key.as_bytes().as_slice())?;

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
    use crate::identity::{IDENTITY_DERIVATION_VERSION, MasterSeed};
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::{
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    const VAULT_NONCE_LEN: usize = 24;

    pub struct VaultPlaintext {
        pub data: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct IdentityVault {
        pub identity_derivation_version: u32,
        #[serde(with = "master_seed_serde")]
        pub master_seed: MasterSeed,
    }

    #[derive(Deserialize, Serialize)]
    pub struct VaultCiphertext {
        pub nonce: [u8; VAULT_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    impl IdentityVault {
        pub fn from_master_seed(master_seed: MasterSeed) -> Self {
            Self {
                identity_derivation_version: IDENTITY_DERIVATION_VERSION,
                master_seed,
            }
        }

        pub fn to_plaintext(&self) -> Result<VaultPlaintext, serde_json::Error> {
            Ok(VaultPlaintext {
                data: serde_json::to_vec(self)?,
            })
        }

        pub fn from_plaintext(plaintext: &VaultPlaintext) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(&plaintext.data)
        }
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

    mod master_seed_serde {
        use super::*;

        pub fn serialize<S>(master_seed: &MasterSeed, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&hex::encode(master_seed))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<MasterSeed, D::Error>
        where
            D: Deserializer<'de>,
        {
            let encoded = String::deserialize(deserializer)?;
            let decoded = hex::decode(encoded).map_err(de::Error::custom)?;

            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| de::Error::invalid_length(decoded.len(), &"64 bytes"))
        }
    }
}

// Manages creation and handling of the file system
pub mod file_system {
    use super::{
        password_kdf::PasswordKdfMetadata, vault::VaultCiphertext, vault_key::WrappedVaultKey,
    };
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use serde::{Deserialize, Serialize};
    use std::{
        error::Error,
        fmt, fs, io,
        path::{Path, PathBuf},
    };

    const LOCAL_ID_LEN: usize = 16;
    const MAX_LOCAL_ID_ATTEMPTS: usize = 16;
    const IDENTITY_RECORD_FILE: &str = "identity_record.json";
    const VAULT_FILE: &str = "vault.enc";

    #[derive(Deserialize, Serialize)]
    pub struct IdentityRecord {
        pub local_hint: String,
        pub password_kdf: PasswordKdfMetadata,
        pub wrapped_vault_key: WrappedVaultKey,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct ListedIdentityStorage {
        pub local_id: String,
        pub local_hint: String,
    }

    pub struct RetrievedIdentityStorage {
        pub identity_record: IdentityRecord,
        pub vault_ciphertext: VaultCiphertext,
    }

    #[derive(Debug)]
    pub enum IdentityStorageError {
        Io(io::Error),
        Json(serde_json::Error),
        LocalIdCollision,
    }

    pub fn generate_random_id() -> String {
        let mut id = [0u8; LOCAL_ID_LEN];
        OsRng.fill_bytes(&mut id);
        hex::encode(id)
    }

    pub fn add_identity(
        identities_dir: &Path,
        identity_record: &IdentityRecord,
        vault_ciphertext: &VaultCiphertext,
    ) -> Result<String, IdentityStorageError> {
        fs::create_dir_all(identities_dir)?;

        let (local_id, identity_dir) = create_identity_dir(identities_dir)?;

        let identity_record_path = identity_dir.join(IDENTITY_RECORD_FILE);
        let vault_path = identity_dir.join(VAULT_FILE);

        fs::write(
            identity_record_path,
            serde_json::to_vec_pretty(identity_record)?,
        )?;
        fs::write(vault_path, serde_json::to_vec(vault_ciphertext)?)?;

        Ok(local_id)
    }

    pub fn list_identities(
        identities_dir: &Path,
    ) -> Result<Vec<ListedIdentityStorage>, IdentityStorageError> {
        if !identities_dir.exists() {
            return Ok(Vec::new());
        }

        let mut identities = Vec::new();

        for entry in fs::read_dir(identities_dir)? {
            let entry = entry?;

            if !entry.file_type()?.is_dir() {
                continue;
            }

            let local_id = entry.file_name().to_string_lossy().into_owned();
            let identity_record = read_identity_record(&entry.path())?;

            identities.push(ListedIdentityStorage {
                local_id,
                local_hint: identity_record.local_hint,
            });
        }

        identities.sort_by(|left, right| {
            left.local_hint
                .cmp(&right.local_hint)
                .then(left.local_id.cmp(&right.local_id))
        });

        Ok(identities)
    }

    pub fn retrieve_identity(
        identities_dir: &Path,
        local_id: &str,
    ) -> Result<RetrievedIdentityStorage, IdentityStorageError> {
        let identity_dir = identity_path(identities_dir, local_id);

        Ok(RetrievedIdentityStorage {
            identity_record: read_identity_record(&identity_dir)?,
            vault_ciphertext: read_vault_ciphertext(&identity_dir)?,
        })
    }

    impl fmt::Display for IdentityStorageError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                IdentityStorageError::Io(err) => write!(f, "identity storage IO failed: {err}"),
                IdentityStorageError::Json(err) => {
                    write!(f, "identity storage serialization failed: {err}")
                }
                IdentityStorageError::LocalIdCollision => {
                    write!(f, "could not create a unique local identity ID")
                }
            }
        }
    }

    impl Error for IdentityStorageError {}

    impl From<io::Error> for IdentityStorageError {
        fn from(err: io::Error) -> Self {
            Self::Io(err)
        }
    }

    impl From<serde_json::Error> for IdentityStorageError {
        fn from(err: serde_json::Error) -> Self {
            Self::Json(err)
        }
    }

    fn create_identity_dir(
        identities_dir: &Path,
    ) -> Result<(String, PathBuf), IdentityStorageError> {
        for _ in 0..MAX_LOCAL_ID_ATTEMPTS {
            let local_id = generate_random_id();
            let identity_dir = identity_path(identities_dir, &local_id);

            match fs::create_dir(&identity_dir) {
                Ok(()) => return Ok((local_id, identity_dir)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err.into()),
            }
        }

        Err(IdentityStorageError::LocalIdCollision)
    }

    fn identity_path(identities_dir: &Path, local_id: &str) -> PathBuf {
        identities_dir.join(local_id)
    }

    fn read_identity_record(identity_dir: &Path) -> Result<IdentityRecord, IdentityStorageError> {
        let identity_record_path = identity_dir.join(IDENTITY_RECORD_FILE);
        let identity_record = fs::read(identity_record_path)?;

        Ok(serde_json::from_slice(&identity_record)?)
    }

    fn read_vault_ciphertext(identity_dir: &Path) -> Result<VaultCiphertext, IdentityStorageError> {
        let vault_path = identity_dir.join(VAULT_FILE);
        let vault_ciphertext = fs::read(vault_path)?;

        Ok(serde_json::from_slice(&vault_ciphertext)?)
    }
}

use crate::identity::MasterSeed;
use std::{error::Error, fmt, path::Path};

#[derive(Debug)]
pub enum CreateIdentityStorageError {
    PasswordKdf(argon2::Error),
    VaultKey(vault_key::VaultKeyError),
    VaultEncryption(chacha20poly1305::Error),
    VaultSerialization(serde_json::Error),
    Storage(file_system::IdentityStorageError),
}

pub struct DecryptedIdentityStorage {
    pub local_hint: String,
    pub master_seed: MasterSeed,
}

#[derive(Debug)]
pub enum DecryptIdentityStorageError {
    Storage(file_system::IdentityStorageError),
    PasswordKdf(argon2::Error),
    VaultKey(vault_key::VaultKeyError),
    VaultDecryption(chacha20poly1305::Error),
    VaultDeserialization(serde_json::Error),
    UnsupportedIdentityDerivationVersion(u32),
}

pub fn create_identity_storage(
    identities_dir: &Path,
    local_hint: String,
    master_seed: MasterSeed,
    password: &str,
) -> Result<String, CreateIdentityStorageError> {
    let identity_vault = vault::IdentityVault::from_master_seed(master_seed);
    let vault_plaintext = identity_vault.to_plaintext()?;

    let vault_key = vault_key::create_vault_key();
    let vault_ciphertext = vault::encrypt_vault(&vault_plaintext, &vault_key)?;

    let password_key = password_kdf::create_password_key(password)?;
    let wrapped_vault_key = vault_key::wrap_vault_key(&vault_key, &password_key)?;

    let identity_record = file_system::IdentityRecord {
        local_hint,
        password_kdf: password_key.metadata,
        wrapped_vault_key,
    };

    Ok(file_system::add_identity(
        identities_dir,
        &identity_record,
        &vault_ciphertext,
    )?)
}

pub fn decrypt_identity_storage(
    identities_dir: &Path,
    local_id: &str,
    password: &str,
) -> Result<DecryptedIdentityStorage, DecryptIdentityStorageError> {
    let retrieved = file_system::retrieve_identity(identities_dir, local_id)?;
    let password_key =
        password_kdf::recreate_password_key(password, &retrieved.identity_record.password_kdf)?;
    let vault_key =
        vault_key::unwrap_vault_key(&retrieved.identity_record.wrapped_vault_key, &password_key)?;
    let vault_plaintext = vault::decrypt_vault(&retrieved.vault_ciphertext, &vault_key)?;
    let identity_vault = vault::IdentityVault::from_plaintext(&vault_plaintext)?;

    if identity_vault.identity_derivation_version != crate::identity::IDENTITY_DERIVATION_VERSION {
        return Err(
            DecryptIdentityStorageError::UnsupportedIdentityDerivationVersion(
                identity_vault.identity_derivation_version,
            ),
        );
    }

    Ok(DecryptedIdentityStorage {
        local_hint: retrieved.identity_record.local_hint,
        master_seed: identity_vault.master_seed,
    })
}

impl fmt::Display for CreateIdentityStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateIdentityStorageError::PasswordKdf(err) => {
                write!(f, "password key creation failed: {err}")
            }
            CreateIdentityStorageError::VaultKey(err) => {
                write!(f, "vault key wrapping failed: {err}")
            }
            CreateIdentityStorageError::VaultEncryption(_) => write!(f, "vault encryption failed"),
            CreateIdentityStorageError::VaultSerialization(err) => {
                write!(f, "vault serialization failed: {err}")
            }
            CreateIdentityStorageError::Storage(err) => write!(f, "identity storage failed: {err}"),
        }
    }
}

impl Error for CreateIdentityStorageError {}

impl fmt::Display for DecryptIdentityStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptIdentityStorageError::Storage(err) => {
                write!(f, "identity storage retrieval failed: {err}")
            }
            DecryptIdentityStorageError::PasswordKdf(err) => {
                write!(f, "password key recreation failed: {err}")
            }
            DecryptIdentityStorageError::VaultKey(err) => {
                write!(f, "vault key unwrapping failed: {err}")
            }
            DecryptIdentityStorageError::VaultDecryption(_) => {
                write!(f, "vault decryption failed")
            }
            DecryptIdentityStorageError::VaultDeserialization(err) => {
                write!(f, "vault deserialization failed: {err}")
            }
            DecryptIdentityStorageError::UnsupportedIdentityDerivationVersion(version) => {
                write!(f, "unsupported identity derivation version: {version}")
            }
        }
    }
}

impl Error for DecryptIdentityStorageError {}

impl From<argon2::Error> for CreateIdentityStorageError {
    fn from(err: argon2::Error) -> Self {
        Self::PasswordKdf(err)
    }
}

impl From<vault_key::VaultKeyError> for CreateIdentityStorageError {
    fn from(err: vault_key::VaultKeyError) -> Self {
        Self::VaultKey(err)
    }
}

impl From<chacha20poly1305::Error> for CreateIdentityStorageError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::VaultEncryption(err)
    }
}

impl From<serde_json::Error> for CreateIdentityStorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::VaultSerialization(err)
    }
}

impl From<file_system::IdentityStorageError> for CreateIdentityStorageError {
    fn from(err: file_system::IdentityStorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<file_system::IdentityStorageError> for DecryptIdentityStorageError {
    fn from(err: file_system::IdentityStorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<argon2::Error> for DecryptIdentityStorageError {
    fn from(err: argon2::Error) -> Self {
        Self::PasswordKdf(err)
    }
}

impl From<vault_key::VaultKeyError> for DecryptIdentityStorageError {
    fn from(err: vault_key::VaultKeyError) -> Self {
        Self::VaultKey(err)
    }
}

impl From<chacha20poly1305::Error> for DecryptIdentityStorageError {
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::VaultDecryption(err)
    }
}

impl From<serde_json::Error> for DecryptIdentityStorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::VaultDeserialization(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecryptIdentityStorageError, create_identity_storage, decrypt_identity_storage,
        file_system, password_kdf, vault, vault_key,
    };
    use std::fs;

    #[test]
    fn recreate_password_key_recreates_the_same_key() {
        let created = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");

        let recreated =
            password_kdf::recreate_password_key("correct horse battery staple", &created.metadata)
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

        let wrapped =
            vault_key::wrap_vault_key(&vault_key, &password_key).expect("vault key should wrap");
        let unwrapped =
            vault_key::unwrap_vault_key(&wrapped, &password_key).expect("vault key should unwrap");

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
        let wrapped =
            vault_key::wrap_vault_key(&vault_key, &password_key).expect("vault key should wrap");

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

    #[test]
    fn identity_vault_serializes_master_seed_and_derivation_version() {
        let master_seed = [42u8; 64];
        let identity_vault = vault::IdentityVault::from_master_seed(master_seed);

        let plaintext = identity_vault
            .to_plaintext()
            .expect("identity vault should serialize");
        let restored = vault::IdentityVault::from_plaintext(&plaintext)
            .expect("identity vault should deserialize");

        assert_eq!(
            restored.identity_derivation_version,
            crate::identity::IDENTITY_DERIVATION_VERSION
        );
        assert_eq!(restored.master_seed, master_seed);
    }

    #[test]
    fn identity_vault_round_trips_through_vault_encryption() {
        let vault_key = vault_key::create_vault_key();
        let master_seed = [7u8; 64];
        let identity_vault = vault::IdentityVault::from_master_seed(master_seed);
        let plaintext = identity_vault
            .to_plaintext()
            .expect("identity vault should serialize");

        let ciphertext =
            vault::encrypt_vault(&plaintext, &vault_key).expect("identity vault should encrypt");
        let decrypted =
            vault::decrypt_vault(&ciphertext, &vault_key).expect("identity vault should decrypt");
        let restored = vault::IdentityVault::from_plaintext(&decrypted)
            .expect("identity vault should deserialize");

        assert_eq!(
            restored.identity_derivation_version,
            crate::identity::IDENTITY_DERIVATION_VERSION
        );
        assert_eq!(restored.master_seed, master_seed);
    }

    #[test]
    fn generate_random_id_returns_hex_local_storage_id() {
        let id = file_system::generate_random_id();

        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn list_identities_returns_empty_list_when_identities_dir_does_not_exist() {
        let identities_dir = std::env::temp_dir()
            .join(format!(
                "resonance-missing-identities-test-{}",
                file_system::generate_random_id()
            ))
            .join("identities");

        let listed =
            file_system::list_identities(&identities_dir).expect("missing dir should list");

        assert!(listed.is_empty());
    }

    #[test]
    fn list_identities_returns_local_ids_and_hints() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-list-identities-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");
        let first_record = test_identity_record("Work");
        let second_record = test_identity_record("Personal");
        let vault_ciphertext = test_vault_ciphertext();

        let first_id = file_system::add_identity(&identities_dir, &first_record, &vault_ciphertext)
            .expect("first identity should be added");
        let second_id =
            file_system::add_identity(&identities_dir, &second_record, &vault_ciphertext)
                .expect("second identity should be added");

        fs::remove_file(identities_dir.join(&first_id).join("vault.enc"))
            .expect("vault should be removable to prove list does not read it");

        let listed = file_system::list_identities(&identities_dir).expect("identities should list");

        assert_eq!(listed.len(), 2);
        assert_eq!(
            listed,
            vec![
                file_system::ListedIdentityStorage {
                    local_id: second_id,
                    local_hint: "Personal".to_string(),
                },
                file_system::ListedIdentityStorage {
                    local_id: first_id,
                    local_hint: "Work".to_string(),
                },
            ]
        );

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    #[test]
    fn retrieve_identity_returns_identity_record_and_vault_ciphertext() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-retrieve-identity-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");
        let identity_record = test_identity_record("Personal");
        let vault_ciphertext = test_vault_ciphertext();

        let local_id =
            file_system::add_identity(&identities_dir, &identity_record, &vault_ciphertext)
                .expect("identity should be added");

        let retrieved = file_system::retrieve_identity(&identities_dir, &local_id)
            .expect("identity should be retrieved");

        assert_eq!(retrieved.identity_record.local_hint, "Personal");
        assert_eq!(retrieved.identity_record.password_kdf.salt, [1u8; 16]);
        assert_eq!(retrieved.identity_record.wrapped_vault_key.nonce, [2u8; 24]);
        assert_eq!(
            retrieved.identity_record.wrapped_vault_key.ciphertext,
            vec![3, 4, 5]
        );
        assert_eq!(retrieved.vault_ciphertext.nonce, [6u8; 24]);
        assert_eq!(retrieved.vault_ciphertext.ciphertext, vec![7, 8, 9]);

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    #[test]
    fn add_identity_creates_identity_folder_and_files() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-identity-manager-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");

        let password_key = password_kdf::create_password_key("correct horse battery staple")
            .expect("password key should be created");
        let vault_key = vault_key::create_vault_key();
        let wrapped_vault_key =
            vault_key::wrap_vault_key(&vault_key, &password_key).expect("vault key should wrap");
        let identity_record = file_system::IdentityRecord {
            local_hint: "Personal".to_string(),
            password_kdf: password_key.metadata,
            wrapped_vault_key,
        };
        let vault_ciphertext = vault::encrypt_vault(
            &vault::VaultPlaintext {
                data: b"encrypted vault payload".to_vec(),
            },
            &vault_key,
        )
        .expect("vault should encrypt");

        let local_id =
            file_system::add_identity(&identities_dir, &identity_record, &vault_ciphertext)
                .expect("identity should be added");

        let identity_dir = identities_dir.join(&local_id);
        let identity_record_file = identity_dir.join("identity_record.json");
        let vault_file = identity_dir.join("vault.enc");

        assert_eq!(local_id.len(), 32);
        assert!(identity_dir.is_dir());
        assert!(identity_record_file.is_file());
        assert!(vault_file.is_file());

        let identity_record_json: serde_json::Value = serde_json::from_slice(
            &fs::read(identity_record_file).expect("identity record should be readable"),
        )
        .expect("identity record should be JSON");
        let vault_json: serde_json::Value =
            serde_json::from_slice(&fs::read(vault_file).expect("vault should be readable"))
                .expect("vault should be JSON");

        assert_eq!(identity_record_json["local_hint"], "Personal");
        assert!(identity_record_json.get("password_kdf").is_some());
        assert!(identity_record_json.get("wrapped_vault_key").is_some());
        assert!(vault_json.get("nonce").is_some());
        assert!(vault_json.get("ciphertext").is_some());

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    #[test]
    fn create_identity_storage_creates_complete_local_storage() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-create-identity-storage-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");

        let local_id = create_identity_storage(
            &identities_dir,
            "Work".to_string(),
            [9u8; 64],
            "correct horse battery staple",
        )
        .expect("identity storage should be created");

        let identity_dir = identities_dir.join(&local_id);
        let identity_record_file = identity_dir.join("identity_record.json");
        let vault_file = identity_dir.join("vault.enc");

        assert_eq!(local_id.len(), 32);
        assert!(identity_dir.is_dir());
        assert!(identity_record_file.is_file());
        assert!(vault_file.is_file());

        let identity_record_json: serde_json::Value = serde_json::from_slice(
            &fs::read(identity_record_file).expect("identity record should be readable"),
        )
        .expect("identity record should be JSON");

        assert_eq!(identity_record_json["local_hint"], "Work");
        assert!(identity_record_json.get("password_kdf").is_some());
        assert!(identity_record_json.get("wrapped_vault_key").is_some());

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    #[test]
    fn decrypt_identity_storage_returns_hint_and_master_seed() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-decrypt-identity-storage-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");
        let master_seed = [11u8; 64];
        let local_id = create_identity_storage(
            &identities_dir,
            "Personal".to_string(),
            master_seed,
            "correct horse battery staple",
        )
        .expect("identity storage should be created");

        let decrypted =
            decrypt_identity_storage(&identities_dir, &local_id, "correct horse battery staple")
                .expect("identity storage should decrypt");

        assert_eq!(decrypted.local_hint, "Personal");
        assert_eq!(decrypted.master_seed, master_seed);

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    #[test]
    fn decrypt_identity_storage_rejects_wrong_password() {
        let test_root = std::env::temp_dir().join(format!(
            "resonance-decrypt-wrong-password-test-{}",
            file_system::generate_random_id()
        ));
        let identities_dir = test_root.join("identities");
        let local_id = create_identity_storage(
            &identities_dir,
            "Personal".to_string(),
            [12u8; 64],
            "correct horse battery staple",
        )
        .expect("identity storage should be created");

        let err = match decrypt_identity_storage(&identities_dir, &local_id, "wrong password") {
            Ok(_) => panic!("wrong password should fail decryption"),
            Err(err) => err,
        };

        assert!(matches!(err, DecryptIdentityStorageError::VaultKey(_)));

        fs::remove_dir_all(test_root).expect("test directory should be removed");
    }

    fn test_identity_record(local_hint: &str) -> file_system::IdentityRecord {
        file_system::IdentityRecord {
            local_hint: local_hint.to_string(),
            password_kdf: password_kdf::PasswordKdfMetadata {
                salt: [1u8; 16],
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 1,
            },
            wrapped_vault_key: vault_key::WrappedVaultKey {
                nonce: [2u8; 24],
                ciphertext: vec![3, 4, 5],
            },
        }
    }

    fn test_vault_ciphertext() -> vault::VaultCiphertext {
        vault::VaultCiphertext {
            nonce: [6u8; 24],
            ciphertext: vec![7, 8, 9],
        }
    }
}
