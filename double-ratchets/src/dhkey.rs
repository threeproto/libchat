use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct DhKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn dh(&self, their_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}
