# Resonance

Resonance is a Rust implementation of a communication protocol for self-owned identity, encrypted messaging, and capability-scoped delivery.

The project is built around a simple constraint: communication should not depend on mandatory global shared state. Resonance is designed around cryptographic identity rather than phone numbers or centrally assigned accounts, with end-to-end encrypted communication that can move across transports without making one provider the center of the system.

This repository is an early-stage implementation of that protocol. The current core is small, sharp, and already covers the foundations:

- 24-word BIP39 seed creation and deterministic identity recovery.
- ML-DSA-65 root identity derivation from domain-separated HKDF output.
- Stable Resonance identity IDs derived from root public keys.
- Password-unlocked local identity vaults using Argon2id and XChaCha20-Poly1305.
- Random per-device storage keys wrapped by seed-derived local wrapping keys.
- Per-message local encryption primitives with authenticated decryption checks.
- Zeroization for key buffers and decrypted secret material handled by the current core.

The full protocol is still under active development. Networking, session establishment, ratcheting, capability delivery, and production-grade message storage are not complete yet.

## Status

Early implementation. APIs and storage formats may change as the protocol and implementation mature.
