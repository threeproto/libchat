use std::collections::HashMap;

use x25519_dalek::PublicKey;

use crate::{
    aead::{decrypt, encrypt},
    hkdf::{kdf_chain, kdf_root},
    keypair::DhKeyPair,
};

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
    }

    pub fn dh_ratchet_send(&mut self) {
        let remote = self.dh_remote.expect("no remote DH key");

        self.dh_self = DhKeyPair::generate();
        let dh_out = self.dh_self.dh(&remote);
        let (new_root, send_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.sending_chain = Some(send_chain);
    }

    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12], Header) {
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
        (ciphertext, nonce, header)
    }

    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        header: Header,
    ) -> Vec<u8> {
        let key_id = (header.dh_pub, header.msg_num);
        if let Some(msg_key) = self.skipped_keys.remove(&key_id) {
            return decrypt(&msg_key, ciphertext, nonce, header.as_bytes());
        }

        if self.dh_remote.as_ref() != Some(&header.dh_pub) {
            self.skip_message_keys(header.prev_chain_len).unwrap();
            self.dh_ratchet_receive(header.dh_pub);
        }

        self.skip_message_keys(header.msg_num).unwrap();

        let chain = self.receiving_chain.as_mut().expect("no receiving chain");
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

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
