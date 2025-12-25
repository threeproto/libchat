use blake2::{Blake2b512, Digest};

pub fn kdf_root(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Blake2b512::new();
    hasher.update(b"DR-root");
    hasher.update(root_key);
    hasher.update(dh_out);

    let result = hasher.finalize();
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&result[..32]);
    chain_key.copy_from_slice(&result[32..64]);
    (new_root, chain_key)
}

pub fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Blake2b512::new();
    hasher.update(b"DR-chain");
    hasher.update(chain_key);

    let result = hasher.finalize();
    let mut next_chain = [0u8; 32];
    let mut message_key = [0u8; 32];
    next_chain.copy_from_slice(&result[..32]);
    message_key.copy_from_slice(&result[32..64]);
    (next_chain, message_key)
}
