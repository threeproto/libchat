use std::collections::HashMap;

use x25519_dalek::PublicKey;

use crate::{
    aead::{decrypt, encrypt},
    hkdf::{kdf_chain, kdf_root},
    keypair::DhKeyPair,
};

#[derive(Clone)]
pub struct RatchetState {
    pub root_key: [u8; 32],

    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,

    pub dh_self: DhKeyPair,
    pub dh_remote: Option<PublicKey>,

    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,

    pub skipped_keys: HashMap<(PublicKey, u32), [u8; 32]>,
}

#[derive(Clone)]
pub struct Header {
    pub dh_pub: PublicKey,
    pub msg_num: u32,
    pub prev_chain_len: u32,
}

impl Header {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.dh_pub.as_bytes()
    }
}

impl RatchetState {
    /// Initialize the party that sends first (Alice)
    pub fn init_sender(shared_secret: [u8; 32], remote_pub: PublicKey) -> Self {
        let dh_self = DhKeyPair::generate();

        // Initial DH
        let dh_out = dh_self.dh(&remote_pub);
        let (root_key, sending_chain) = kdf_root(&shared_secret, &dh_out);

        Self {
            root_key,

            sending_chain: Some(sending_chain),
            receiving_chain: None,

            dh_self,
            dh_remote: Some(remote_pub),

            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,

            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize the party that receives first (Bob)
    pub fn init_receiver(shared_secret: [u8; 32], dh_self: DhKeyPair) -> Self {
        Self {
            root_key: shared_secret,

            sending_chain: None,
            receiving_chain: None, // derived on first receive

            dh_self,
            dh_remote: None,

            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,

            skipped_keys: HashMap::new(),
        }
    }

    pub fn dh_ratchet_receive(&mut self, remote_pub: PublicKey) {
        let dh_out = self.dh_self.dh(&remote_pub);
        let (new_root, recv_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.receiving_chain = Some(recv_chain);
        self.sending_chain = None; // 🔥 important
        self.dh_remote = Some(remote_pub);
        self.msg_recv = 0;
    }

    pub fn dh_ratchet_send(&mut self) {
        let remote = self.dh_remote.expect("no remote DH key");

        self.dh_self = DhKeyPair::generate();
        let dh_out = self.dh_self.dh(&remote);
        let (new_root, send_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.sending_chain = Some(send_chain);
    }

    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> (Vec<u8>, Header) {
        if self.sending_chain.is_none() {
            self.dh_ratchet_send();
            self.prev_chain_len = self.msg_send;
            self.msg_send = 0;
        }

        let chain = self.sending_chain.as_mut().unwrap();
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        let header = Header {
            dh_pub: self.dh_self.public,
            msg_num: self.msg_send,
            prev_chain_len: self.prev_chain_len,
        };

        self.msg_send += 1;

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, header.as_bytes());

        let mut ciphertext_with_nonce = Vec::with_capacity(nonce.len() + ciphertext.len());
        ciphertext_with_nonce.extend_from_slice(&nonce);
        ciphertext_with_nonce.extend_from_slice(&ciphertext);

        (ciphertext_with_nonce, header)
    }

    pub fn decrypt_message(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: Header,
    ) -> Result<Vec<u8>, String> {
        assert!(ciphertext_with_nonce.len() >= 12, "ciphertext too short");
        let (nonce_slice, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce: &[u8; 12] = nonce_slice.try_into().unwrap();

        let key_id = (header.dh_pub, header.msg_num);
        if let Some(msg_key) = self.skipped_keys.remove(&key_id) {
            return decrypt(&msg_key, ciphertext, nonce, header.as_bytes());
        }

        if self.dh_remote.as_ref() == Some(&header.dh_pub) && header.msg_num < self.msg_recv {
            return Err("Message replay detected".to_string());
        }

        if self.dh_remote.as_ref() != Some(&header.dh_pub) {
            self.skip_message_keys(header.prev_chain_len)?;
            self.dh_ratchet_receive(header.dh_pub);
            self.prev_chain_len = header.msg_num; // Important: update prev_chain_len after ratchet
        }

        self.skip_message_keys(header.msg_num)?;

        let chain = self.receiving_chain.as_mut().expect("no receiving chain");
        let (next_chain, message_key) = kdf_chain(chain);

        *chain = next_chain;
        self.msg_recv += 1;

        decrypt(&message_key, ciphertext, nonce, header.as_bytes())
    }

    pub fn skip_message_keys(&mut self, until: u32) -> Result<(), &'static str> {
        const MAX_SKIP: u32 = 10;

        if self.msg_recv + MAX_SKIP < until {
            return Err("too many skipped messages");
        }

        while self.msg_recv < until {
            let chain = self.receiving_chain.as_mut().unwrap();
            let (next_chain, msg_key) = kdf_chain(chain);
            *chain = next_chain;

            let key_id = (self.dh_remote.unwrap(), self.msg_recv);
            self.skipped_keys.insert(key_id, msg_key);
            self.msg_recv += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_alice_bob() -> (RatchetState, RatchetState, [u8; 32]) {
        // Simulate pre-shared secret (e.g., from X3DH)
        let shared_secret = [0x42; 32];

        // Bob generates his long-term keypair
        let bob_keypair = DhKeyPair::generate();

        // Alice initializes as sender, knowing Bob's public key
        let alice = RatchetState::init_sender(shared_secret, bob_keypair.public);

        // Bob initializes as receiver with his private key
        let bob = RatchetState::init_receiver(shared_secret, bob_keypair);

        (alice, bob, shared_secret)
    }

    #[test]
    fn test_basic_roundtrip_one_message() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let plaintext = b"Hello Bob, this is Alice!";

        let (ciphertext_with_nonce, header) = alice.encrypt_message(plaintext);

        let decrypted = bob.decrypt_message(&ciphertext_with_nonce, header).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(alice.msg_send, 1);
        assert_eq!(bob.msg_recv, 1);
    }

    #[test]
    fn test_multiple_messages_in_order() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let messages = [b"Message 1", b"Message 2", b"message 3"];

        for msg in messages {
            let (ct, header) = alice.encrypt_message(msg);
            let pt = bob.decrypt_message(&ct, header).unwrap();
            assert_eq!(pt, msg);
        }

        assert_eq!(alice.msg_send, 3);
        assert_eq!(bob.msg_recv, 3);
    }

    #[test]
    fn test_out_of_order_messages_with_skipped_keys() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends 3 messages
        let mut sent = vec![];
        for i in 0..3 {
            let plaintext = format!("Message {}", i + 1).into_bytes();
            let (ct, header) = alice.encrypt_message(&plaintext);
            sent.push((ct, header, plaintext));
        }

        // Bob receives them out of order: 0, 2, 1
        let decrypted0 = bob.decrypt_message(&sent[0].0, sent[0].1.clone()).unwrap();
        assert_eq!(decrypted0, sent[0].2);

        let decrypted2 = bob.decrypt_message(&sent[2].0, sent[2].1.clone()).unwrap();
        assert_eq!(decrypted2, sent[2].2);

        let decrypted1 = bob.decrypt_message(&sent[1].0, sent[1].1.clone()).unwrap();
        assert_eq!(decrypted1, sent[1].2);

        assert_eq!(bob.msg_recv, 3);
    }

    #[test]
    fn test_sender_ratchets_after_receiving_from_other_side() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends one message
        let (ct, header) = alice.encrypt_message(b"first");
        bob.decrypt_message(&ct, header).unwrap();

        // Bob performs DH ratchet by trying to send
        let old_bob_pub = bob.dh_self.public;
        let (bob_ct, bob_header) = {
            let mut b = bob.clone();
            b.encrypt_message(b"reply")
        };
        assert_ne!(bob_header.dh_pub, old_bob_pub);

        // Alice receives Bob's message with new DH pub → ratchets
        let old_alice_pub = alice.dh_self.public;
        let old_root = alice.root_key;

        // Even if decrypt fails (wrong key), ratchet should happen
        alice.decrypt_message(&bob_ct, bob_header).unwrap();

        // Now Alice sends → should do DH ratchet
        let (_, final_header) = alice.encrypt_message(b"after both ratcheted");

        assert_ne!(final_header.dh_pub, old_alice_pub);
        assert_ne!(alice.root_key, old_root);
    }

    #[test]
    fn test_max_skip_limit_enforced() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends message 0
        let (_, _) = alice.encrypt_message(b"First");

        // Now Alice skips many messages (simulate lost packets)
        for _ in 0..15 {
            alice.encrypt_message(b"lost");
        }

        // Alice sends final message
        let (ct_final, header_final) = alice.encrypt_message(b"Final");

        // Bob tries to decrypt final — should fail because too many skipped
        let result = bob.decrypt_message(&ct_final, header_final);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "too many skipped messages");
    }

    #[test]
    fn test_aad_authenticates_header() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let (ct, mut header) = alice.encrypt_message(b"Sensitive data");

        // Tamper with header (change DH pub byte)
        let mut tampered_pub_bytes = header.dh_pub.to_bytes();
        tampered_pub_bytes[0] ^= 0xff;
        header.dh_pub = PublicKey::from(tampered_pub_bytes);

        let result = bob.decrypt_message(&ct, header);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Decryption failed"));
    }

    #[test]
    fn test_full_asymmetric_ratchet_conversation() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends first few
        for i in 0..3 {
            let msg = format!("A -> B {}", i).into_bytes();
            let (ct, h) = alice.encrypt_message(&msg);
            let pt = bob.decrypt_message(&ct, h).unwrap();
            assert_eq!(pt, msg);
        }

        // Bob now responds — this should trigger his first DH ratchet
        let (ct_b, h_b) = bob.encrypt_message(b"B -> A response");

        // Alice receives Bob's message
        let pt_a = alice.decrypt_message(&ct_b, h_b).unwrap();
        assert_eq!(pt_a, b"B -> A response");

        // Both should now have performed a DH ratchet
        assert!(alice.receiving_chain.is_some());
        assert!(bob.sending_chain.is_some());
    }

    #[test]
    fn test_skipped_keys_are_one_time_use() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let msgs = vec![b"msg0", b"msg1", b"msg2", b"msg3"];

        let mut encrypted = vec![];
        for msg in msgs {
            let (ct, h) = alice.encrypt_message(msg);
            encrypted.push((ct, h));
        }

        // Receive msg0 and msg2 → msg1 goes to skipped
        bob.decrypt_message(&encrypted[0].0, encrypted[0].1.clone())
            .unwrap();
        bob.decrypt_message(&encrypted[2].0, encrypted[2].1.clone())
            .unwrap();

        // Now receive msg1 — should use skipped key and remove it
        let pt1 = bob
            .decrypt_message(&encrypted[1].0, encrypted[1].1.clone())
            .unwrap();
        assert_eq!(pt1, b"msg1");

        // Try to decrypt msg1 again → should fail (key was removed)
        let result = bob.decrypt_message(&encrypted[1].0, encrypted[1].1.clone());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Message replay detected"));
    }
}
