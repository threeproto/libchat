use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, AeadCore, Payload},
};
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Performs key derivation for the root ratchet step using BLAKE2b.
/// Outputs a new root key and chain key.
fn kdf_root(key: &[u8], shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Blake2b::<U64>::new_keyed(b"DOUBLE_RATCHET_KDF_ROOT_KEY");
    hasher.update(key);
    hasher.update(shared_secret);
    let output = hasher.finalize();
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];
    root_key.copy_from_slice(&output[0..32]);
    chain_key.copy_from_slice(&output[32..64]);
    (root_key, chain_key)
}

/// Performs key derivation for the symmetric chain ratchet step using BLAKE2b.
/// Outputs a new chain key and message key.
fn kdf_chain_key(key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Blake2b::<U64>::new_keyed(b"DOUBLE_RATCHET_KDF_CHAIN_KEY");
    hasher.update(key);
    let output = hasher.finalize();
    let mut chain_key = [0u8; 32];
    let mut message_key = [0u8; 32];
    chain_key.copy_from_slice(&output[0..32]);
    message_key.copy_from_slice(&output[32..64]);
    (chain_key, message_key)
}

/// Simplified Double Ratchet state.
#[derive(Clone)]
struct DoubleRatchet {
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    send_ratchet_secret: StaticSecret,
    recv_ratchet_public: Option<PublicKey>,
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,
}

impl DoubleRatchet {
    /// Initialize as the initiator (e.g., Alice), with a pre-shared secret and the responder's ratchet public key.
    pub fn init_initiator(shared_secret: [u8; 32], remote_ratchet_pub: PublicKey) -> Self {
        let send_ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let dh_out: SharedSecret = send_ratchet_secret.diffie_hellman(&remote_ratchet_pub);
        let (new_root, new_recv_chain) = kdf_root(&shared_secret, dh_out.as_bytes());

        // Generate new sending ratchet key pair and perform second ratchet step.
        let send_ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let dh_out: SharedSecret = send_ratchet_secret.diffie_hellman(&remote_ratchet_pub);
        let (new_root, new_send_chain) = kdf_root(&new_root, dh_out.as_bytes());

        Self {
            root_key: new_root,
            send_chain_key: new_send_chain,
            recv_chain_key: new_recv_chain,
            send_ratchet_secret,
            recv_ratchet_public: Some(remote_ratchet_pub),
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        }
    }

    /// Initialize as the responder (e.g., Bob), with a pre-shared secret and your own ratchet private key.
    pub fn init_responder(shared_secret: [u8; 32], own_ratchet_secret: StaticSecret) -> Self {
        Self {
            root_key: shared_secret,
            send_chain_key: [0; 32],
            recv_chain_key: [0; 32],
            send_ratchet_secret: own_ratchet_secret,
            recv_ratchet_public: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        }
    }

    /// Perform a DH ratchet step when a new remote ratchet public key is received.
    fn ratchet(&mut self, remote_pub: PublicKey) {
        self.prev_send_count = self.send_count;
        let dh_out: SharedSecret = self.send_ratchet_secret.diffie_hellman(&remote_pub);
        let (new_root, new_recv_chain) = kdf_root(&self.root_key, dh_out.as_bytes());
        self.root_key = new_root;
        self.recv_chain_key = new_recv_chain;
        self.recv_ratchet_public = Some(remote_pub);

        // Generate new sending ratchet key pair and ratchet forward.
        self.send_ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let dh_out: SharedSecret = self.send_ratchet_secret.diffie_hellman(&remote_pub);
        let (new_root, new_send_chain) = kdf_root(&self.root_key, dh_out.as_bytes());
        self.root_key = new_root;
        self.send_chain_key = new_send_chain;
        self.send_count = 0;
        self.recv_count = 0;
    }

    /// Encrypt a message. Returns (ciphertext, nonce, current ratchet public key to include in header).
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (Vec<u8>, [u8; 12], PublicKey) {
        let (new_chain_key, message_key) = kdf_chain_key(&self.send_chain_key);
        self.send_chain_key = new_chain_key;
        let cipher = ChaCha20Poly1305::new_from_slice(&message_key).unwrap();

        // Use a deterministic nonce based on message count (padded to 12 bytes).
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.send_count.to_le_bytes());
        let nonce = nonce_bytes.into();

        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        let ciphertext = cipher.encrypt(&nonce, payload).unwrap();

        self.send_count += 1;

        (
            ciphertext,
            nonce_bytes,
            self.send_ratchet_secret.to_public(),
        )
    }

    /// Decrypt a message. Provide the sender's ratchet public key from the message header.
    /// Ratchets if the public key is new.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        ad: &[u8],
        sender_ratchet_pub: PublicKey,
    ) -> Result<Vec<u8>, ()> {
        if self.recv_ratchet_public != Some(sender_ratchet_pub) {
            self.ratchet(sender_ratchet_pub);
        }

        let (new_chain_key, message_key) = kdf_chain_key(&self.recv_chain_key);
        self.recv_chain_key = new_chain_key;
        let cipher = ChaCha20Poly1305::new_from_slice(&message_key).unwrap();

        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };
        let plaintext = cipher.decrypt(nonce.into(), payload).map_err(|_| ())?;

        self.recv_count += 1;

        Ok(plaintext)
    }
}

// Example usage (simplified; in practice, serialize headers with public key, count, prev_count, etc.).
fn main() {
    let shared_secret = {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        buf
    };

    // Bob generates initial ratchet key pair.
    let bob_ratchet_secret = StaticSecret::random_from_rng(OsRng);
    let bob_ratchet_pub = bob_ratchet_secret.to_public();

    // Alice initializes as initiator.
    let mut alice = DoubleRatchet::init_initiator(shared_secret, bob_ratchet_pub);

    // Bob initializes as responder.
    let mut bob = DoubleRatchet::init_responder(shared_secret, bob_ratchet_secret);

    // Alice sends a message.
    let ad = b"header_data"; // In practice, serialized header (public key, counts).
    let plaintext = b"Hello, Bob!";
    let (ciphertext, nonce, alice_pub) = alice.encrypt(plaintext, ad);

    // Bob receives and decrypts (providing Alice's ratchet public from header).
    let decrypted = bob.decrypt(&ciphertext, &nonce, ad, alice_pub).unwrap();
    assert_eq!(decrypted, plaintext);

    // Bob replies.
    let plaintext_reply = b"Hello, Alice!";
    let (ciphertext_reply, nonce_reply, bob_pub) = bob.encrypt(plaintext_reply, ad);

    // Alice receives and decrypts.
    let decrypted_reply = alice
        .decrypt(&ciphertext_reply, &nonce_reply, ad, bob_pub)
        .unwrap();
    assert_eq!(decrypted_reply, plaintext_reply);
}
