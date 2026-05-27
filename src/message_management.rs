pub use message_crypto::{EncryptedMessage, PlaintextMessage, decrypt_message, encrypt_message};
pub use storage_key::{
    MessageStorageKey, MessageStorageKeyError, WrappedMessageStorageKey,
    create_message_storage_key, unwrap_message_storage_key, wrap_message_storage_key,
};

mod storage_key {
    use crate::identity::LocalStorageWrappingKey;
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::{
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };
    use std::{error::Error, fmt};
    use zeroize::Zeroize;

    const MESSAGE_STORAGE_KEY_LEN: usize = 32;
    const MESSAGE_STORAGE_KEY_WRAP_NONCE_LEN: usize = 24;

    pub struct MessageStorageKey {
        key: [u8; MESSAGE_STORAGE_KEY_LEN],
    }

    pub struct WrappedMessageStorageKey {
        pub nonce: [u8; MESSAGE_STORAGE_KEY_WRAP_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    #[derive(Debug)]
    pub enum MessageStorageKeyError {
        Aead(chacha20poly1305::Error),
        InvalidMessageStorageKeyLength(usize),
    }

    impl MessageStorageKey {
        pub(crate) fn as_bytes(&self) -> &[u8; MESSAGE_STORAGE_KEY_LEN] {
            &self.key
        }
    }

    impl Drop for MessageStorageKey {
        fn drop(&mut self) {
            self.key.zeroize();
        }
    }

    pub fn create_message_storage_key() -> MessageStorageKey {
        let mut key = [0u8; MESSAGE_STORAGE_KEY_LEN];
        OsRng.fill_bytes(&mut key);

        MessageStorageKey { key }
    }

    pub fn wrap_message_storage_key(
        message_storage_key: &MessageStorageKey,
        wrapping_key: &LocalStorageWrappingKey,
    ) -> Result<WrappedMessageStorageKey, MessageStorageKeyError> {
        let mut nonce = [0u8; MESSAGE_STORAGE_KEY_WRAP_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let cipher = cipher_from_wrapping_key(wrapping_key);
        let ciphertext = cipher.encrypt(
            XNonce::from_slice(&nonce),
            message_storage_key.as_bytes().as_slice(),
        )?;

        Ok(WrappedMessageStorageKey { nonce, ciphertext })
    }

    pub fn unwrap_message_storage_key(
        wrapped_message_storage_key: &WrappedMessageStorageKey,
        wrapping_key: &LocalStorageWrappingKey,
    ) -> Result<MessageStorageKey, MessageStorageKeyError> {
        let cipher = cipher_from_wrapping_key(wrapping_key);
        let mut plaintext = cipher.decrypt(
            XNonce::from_slice(&wrapped_message_storage_key.nonce),
            wrapped_message_storage_key.ciphertext.as_ref(),
        )?;

        if plaintext.len() != MESSAGE_STORAGE_KEY_LEN {
            let len = plaintext.len();
            plaintext.zeroize();
            return Err(MessageStorageKeyError::InvalidMessageStorageKeyLength(len));
        }

        let mut key = [0u8; MESSAGE_STORAGE_KEY_LEN];
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();

        Ok(MessageStorageKey { key })
    }

    impl fmt::Display for MessageStorageKeyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                MessageStorageKeyError::Aead(_) => {
                    write!(f, "message storage key authentication failed")
                }
                MessageStorageKeyError::InvalidMessageStorageKeyLength(len) => {
                    write!(f, "invalid message storage key length: {len}")
                }
            }
        }
    }

    impl Error for MessageStorageKeyError {}

    impl From<chacha20poly1305::Error> for MessageStorageKeyError {
        fn from(err: chacha20poly1305::Error) -> Self {
            Self::Aead(err)
        }
    }

    fn cipher_from_wrapping_key(wrapping_key: &LocalStorageWrappingKey) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(wrapping_key))
    }
}

mod message_crypto {
    use super::storage_key::MessageStorageKey;
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    use chacha20poly1305::{
        Key, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit},
    };

    const STORED_MESSAGE_NONCE_LEN: usize = 24;

    pub struct PlaintextMessage {
        pub data: Vec<u8>,
    }

    pub struct EncryptedMessage {
        pub nonce: [u8; STORED_MESSAGE_NONCE_LEN],
        pub ciphertext: Vec<u8>,
    }

    pub fn encrypt_message(
        plaintext_message: &PlaintextMessage,
        message_storage_key: &MessageStorageKey,
    ) -> Result<EncryptedMessage, chacha20poly1305::Error> {
        let mut nonce = [0u8; STORED_MESSAGE_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let cipher = cipher_from_message_storage_key(message_storage_key);
        let ciphertext = cipher.encrypt(
            XNonce::from_slice(&nonce),
            plaintext_message.data.as_slice(),
        )?;

        Ok(EncryptedMessage { nonce, ciphertext })
    }

    pub fn decrypt_message(
        encrypted_message: &EncryptedMessage,
        message_storage_key: &MessageStorageKey,
    ) -> Result<PlaintextMessage, chacha20poly1305::Error> {
        let cipher = cipher_from_message_storage_key(message_storage_key);
        let data = cipher.decrypt(
            XNonce::from_slice(&encrypted_message.nonce),
            encrypted_message.ciphertext.as_ref(),
        )?;

        Ok(PlaintextMessage { data })
    }

    fn cipher_from_message_storage_key(
        message_storage_key: &MessageStorageKey,
    ) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(message_storage_key.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_message_storage_key_creates_random_32_byte_key() {
        let first_key: MessageStorageKey = create_message_storage_key();
        let second_key = create_message_storage_key();

        assert_eq!(first_key.as_bytes().len(), 32);
        assert_ne!(first_key.as_bytes(), &[0u8; 32]);
        assert_ne!(first_key.as_bytes(), second_key.as_bytes());
    }

    #[test]
    fn wrapped_message_storage_key_unwraps_to_original_key() {
        let wrapping_key = crate::identity::messages_storage_wrapping_key_from_seed(&[42u8; 64]);
        let message_storage_key = create_message_storage_key();

        let wrapped: WrappedMessageStorageKey =
            wrap_message_storage_key(&message_storage_key, &wrapping_key)
                .expect("message storage key should wrap");
        let unwrapped = unwrap_message_storage_key(&wrapped, &wrapping_key)
            .expect("message storage key should unwrap");

        assert_eq!(message_storage_key.as_bytes(), unwrapped.as_bytes());
        assert_ne!(wrapped.nonce, [0u8; 24]);
        assert_ne!(
            wrapped.ciphertext,
            message_storage_key.as_bytes().as_slice()
        );
    }

    #[test]
    fn wrapped_message_storage_key_rejects_wrong_wrapping_key() {
        let wrapping_key = crate::identity::messages_storage_wrapping_key_from_seed(&[42u8; 64]);
        let wrong_wrapping_key =
            crate::identity::messages_storage_wrapping_key_from_seed(&[7u8; 64]);
        let message_storage_key = create_message_storage_key();
        let wrapped = wrap_message_storage_key(&message_storage_key, &wrapping_key)
            .expect("message storage key should wrap");

        let err = match unwrap_message_storage_key(&wrapped, &wrong_wrapping_key) {
            Ok(_) => panic!("wrong wrapping key should fail authentication"),
            Err(err) => err,
        };

        assert!(matches!(err, MessageStorageKeyError::Aead(_)));
    }

    #[test]
    fn message_encrypts_and_decrypts_with_storage_key() {
        let message_storage_key = create_message_storage_key();
        let plaintext = PlaintextMessage {
            data: b"local plaintext message".to_vec(),
        };

        let encrypted: EncryptedMessage =
            encrypt_message(&plaintext, &message_storage_key).expect("message should encrypt");
        let decrypted =
            decrypt_message(&encrypted, &message_storage_key).expect("message should decrypt");

        assert_eq!(decrypted.data, plaintext.data);
        assert_ne!(encrypted.nonce, [0u8; 24]);
        assert_ne!(encrypted.ciphertext, plaintext.data);
    }

    #[test]
    fn message_decryption_rejects_wrong_storage_key() {
        let message_storage_key = create_message_storage_key();
        let wrong_message_storage_key = create_message_storage_key();
        let plaintext = PlaintextMessage {
            data: b"local plaintext message".to_vec(),
        };
        let encrypted =
            encrypt_message(&plaintext, &message_storage_key).expect("message should encrypt");

        let result = decrypt_message(&encrypted, &wrong_message_storage_key);

        assert!(result.is_err());
    }

    #[test]
    fn message_decryption_rejects_tampered_ciphertext() {
        let message_storage_key = create_message_storage_key();
        let plaintext = PlaintextMessage {
            data: b"local plaintext message".to_vec(),
        };
        let mut encrypted =
            encrypt_message(&plaintext, &message_storage_key).expect("message should encrypt");
        encrypted.ciphertext[0] ^= 1;

        let result = decrypt_message(&encrypted, &message_storage_key);

        assert!(result.is_err());
    }
}
