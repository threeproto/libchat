use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

pub fn encrypt(message_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));
    let nonce = rand::random::<[u8; 12]>();
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failure");
    (ciphertext, nonce)
}

pub fn decrypt(message_key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .expect("decryption failure")
}
