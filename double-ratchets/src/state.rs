use x25519_dalek::PublicKey;

use crate::{
    dhkey::DhKeyPair,
    encryption::{decrypt, encrypt},
    kdf::{kdf_chain, kdf_root},
};

pub struct RatchetState {
    pub root_key: [u8; 32],

    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,

    pub dh_self: DhKeyPair,
    pub dh_remote: Option<PublicKey>,
}

impl RatchetState {
    pub fn dh_ratchet(&mut self, remote_pub: PublicKey) {
        let dh_out = self.dh_self.dh(&remote_pub);
        let (new_root, recv_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.receiving_chain = Some(recv_chain);
        self.dh_remote = Some(remote_pub);

        // generate new DH key
        self.dh_self = DhKeyPair::generate();
        let dh_out = self.dh_self.dh(self.dh_remote.as_ref().unwrap());
        let (new_root, send_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.sending_chain = Some(send_chain);
    }
}

impl RatchetState {
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12], PublicKey) {
        let chain = self.sending_chain.as_mut().expect("no sending chain");
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        let aad = self.dh_self.public.as_bytes();
        let (ciphertext, nonce) = encrypt(&message_key, plaintext, aad);
        (ciphertext, nonce, self.dh_self.public)
    }
}

impl RatchetState {
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        sender_pub: PublicKey,
    ) -> Vec<u8> {
        if self.dh_remote.as_ref() != Some(&sender_pub) {
            self.dh_ratchet(sender_pub);
        }

        let chain = self.receiving_chain.as_mut().expect("no receiving chain");
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        let aad = sender_pub.as_bytes();
        decrypt(&message_key, ciphertext, nonce, aad)
    }
}
