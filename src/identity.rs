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
