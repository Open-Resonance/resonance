use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use ml_dsa::{KeyExport as _, Keypair as _, MlDsa65, Seed as MlDsaSeed, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};

pub type IdentitySeed = [u8; 64];

// Domain Separation label format: resonance:<layer>:<object>:<purpose>:<algorithm>:<version>
const IDENTITY_HKDF_SALT: &[u8] = b"resonance:identity:seed:hkdf-salt:hkdf-sha3-256:v1";
const ROOT_ML_DSA_SEED_LABEL: &[u8] = b"resonance:identity:root-key:seed:ml-dsa-65:v1";
const IDENTITY_ID_LABEL: &[u8] = b"resonance:identity:public-key:id:sha3-256:v1";

pub struct Identity {
    pub root_public_key: VerifyingKey<MlDsa65>,
    pub(crate) root_secret_key: SigningKey<MlDsa65>,
    pub id: String,
}

pub struct PublicIdentity {
    pub id: String,
    pub root_public_key: Vec<u8>,
}

pub fn generate_mnemonic() -> Result<Mnemonic, bip39::Error> {
    Mnemonic::generate_in(Language::English, 24)
}

pub fn seed_from_mnemonic(mnemonic: &Mnemonic) -> IdentitySeed {
    mnemonic.to_seed("")
}

pub(crate) fn derive_seed_material<const N: usize>(seed: &IdentitySeed, label: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha3_256>::new(Some(IDENTITY_HKDF_SALT), seed);
    let mut output = [0u8; N];
    hk.expand(label, &mut output)
        .expect("HKDF output length must be at most 255 times the hash length");
    output
}

pub fn identity_from_seed(seed: &IdentitySeed) -> Identity {
    let root_seed = derive_root_seed(seed);
    let root_secret_key = SigningKey::<MlDsa65>::from_seed(&root_seed);
    let root_public_key = root_secret_key.verifying_key();

    let id = identity_id_from_public_key(&root_public_key.to_bytes());

    Identity {
        root_public_key,
        root_secret_key,
        id,
    }
}

pub fn public_identity(identity: &Identity) -> PublicIdentity {
    PublicIdentity {
        id: identity.id.clone(),
        root_public_key: identity.root_public_key.to_bytes().to_vec(),
    }
}

fn identity_id_from_public_key(public_key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(IDENTITY_ID_LABEL);
    hasher.update(public_key);

    let hash = hasher.finalize();
    let short_hash = &hash[..16];
    format!("rsn:{}", hex::encode(short_hash))
}

fn derive_root_seed(seed: &IdentitySeed) -> MlDsaSeed {
    let root_seed = derive_seed_material::<32>(seed, ROOT_ML_DSA_SEED_LABEL);
    MlDsaSeed::try_from(&root_seed[..]).expect("root ML-DSA seed is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Signer as _, Verifier as _};

    #[test]
    fn domain_separation_labels_follow_protocol_format() {
        assert_domain_label(IDENTITY_HKDF_SALT);
        assert_domain_label(ROOT_ML_DSA_SEED_LABEL);
        assert_domain_label(IDENTITY_ID_LABEL);
    }

    #[test]
    fn generate_mnemonic_creates_twenty_four_english_words() {
        let mnemonic = generate_mnemonic().expect("mnemonic generation should succeed");

        assert_eq!(mnemonic.language(), Language::English);
        assert_eq!(mnemonic.word_count(), 24);
        assert_eq!(mnemonic.to_string().split_whitespace().count(), 24);
    }

    #[test]
    fn seed_from_mnemonic_is_deterministic() {
        let mnemonic = fixed_mnemonic();

        let first_seed = seed_from_mnemonic(&mnemonic);
        let second_seed = seed_from_mnemonic(&mnemonic);

        assert_eq!(first_seed, second_seed);
        assert_ne!(first_seed, [0u8; 64]);
    }

    #[test]
    fn derive_seed_material_is_deterministic_and_domain_separated() {
        let seed = [42u8; 64];

        let first_root_seed = derive_seed_material::<32>(&seed, ROOT_ML_DSA_SEED_LABEL);
        let second_root_seed = derive_seed_material::<32>(&seed, ROOT_ML_DSA_SEED_LABEL);
        let other_seed =
            derive_seed_material::<32>(&seed, b"resonance:identity:test-key:seed:test:v1");
        let longer_seed = derive_seed_material::<64>(&seed, ROOT_ML_DSA_SEED_LABEL);
        let second_longer_seed = derive_seed_material::<64>(&seed, ROOT_ML_DSA_SEED_LABEL);

        assert_eq!(first_root_seed, second_root_seed);
        assert_ne!(first_root_seed, other_seed);
        assert_eq!(longer_seed, second_longer_seed);
        assert_eq!(longer_seed.len(), 64);
        assert_eq!(first_root_seed.as_slice(), &longer_seed[..32]);
    }

    #[test]
    fn identity_from_seed_recovers_the_same_root_identity() {
        let seed = seed_from_mnemonic(&fixed_mnemonic());

        let first_identity = identity_from_seed(&seed);
        let second_identity = identity_from_seed(&seed);

        assert_eq!(first_identity.id, second_identity.id);
        assert_eq!(
            first_identity.root_public_key.to_bytes(),
            second_identity.root_public_key.to_bytes()
        );
        assert_eq!(
            first_identity.root_secret_key.to_bytes(),
            second_identity.root_secret_key.to_bytes()
        );
    }

    #[test]
    fn different_seeds_create_different_root_identities() {
        let first_identity = identity_from_seed(&[1u8; 64]);
        let second_identity = identity_from_seed(&[2u8; 64]);

        assert_ne!(first_identity.id, second_identity.id);
        assert_ne!(
            first_identity.root_public_key.to_bytes(),
            second_identity.root_public_key.to_bytes()
        );
        assert_ne!(
            first_identity.root_secret_key.to_bytes(),
            second_identity.root_secret_key.to_bytes()
        );
    }

    #[test]
    fn root_key_can_sign_and_verify_messages() {
        let identity = identity_from_seed(&seed_from_mnemonic(&fixed_mnemonic()));
        let message = b"resonance identity test message";

        let signature = identity.root_secret_key.sign(message);

        identity
            .root_public_key
            .verify(message, &signature)
            .expect("root public key should verify root secret key signatures");
    }

    #[test]
    fn public_identity_contains_only_public_identity_material() {
        let identity = identity_from_seed(&seed_from_mnemonic(&fixed_mnemonic()));

        let public = public_identity(&identity);

        assert_eq!(public.id, identity.id);
        assert_eq!(public.root_public_key, identity.root_public_key.to_bytes().to_vec());
    }

    #[test]
    fn identity_id_is_domain_separated_and_formatted() {
        let public_key = b"public key bytes";
        let id = identity_id_from_public_key(public_key);

        let mut hasher = Sha3_256::new();
        hasher.update(IDENTITY_ID_LABEL);
        hasher.update(public_key);
        let expected_hash = hasher.finalize();
        let expected_id = format!("rsn:{}", hex::encode(&expected_hash[..16]));

        assert_eq!(id, expected_id);
        assert_ne!(id, format!("rsn:{}", hex::encode(&Sha3_256::digest(public_key)[..16])));
        assert_eq!(id.len(), 36);
        assert!(id.starts_with("rsn:"));
        assert!(id[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    fn fixed_mnemonic() -> Mnemonic {
        Mnemonic::from_entropy(&[0u8; 32]).expect("zero entropy is a valid 24-word mnemonic")
    }

    fn assert_domain_label(label: &[u8]) {
        let label = std::str::from_utf8(label).expect("domain label should be UTF-8");
        let parts = label.split(':').collect::<Vec<_>>();

        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "resonance");
        assert!(parts[1..5].iter().all(|part| !part.is_empty()));
        assert!(parts[5].starts_with('v'));
        assert!(parts[5][1..].chars().all(|c| c.is_ascii_digit()));
    }
}
