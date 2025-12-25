use hkdf::Hkdf;
use sha2::Sha256;

const DOMAIN_ROOT: &[u8] = b"DoubleRatchetRootKey";

pub fn kdf_root(root: &[u8; 32], dh: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root), dh);

    let mut okm = [0u8; 64];
    hk.expand(DOMAIN_ROOT, &mut okm).unwrap();

    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    (new_root, chain)
}

pub fn kdf_chain(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, chain);

    let mut msg_key = [0u8; 32];
    let mut next_chain = [0u8; 32];

    hk.expand(&[0x01], &mut msg_key).unwrap();
    hk.expand(&[0x02], &mut next_chain).unwrap();

    (msg_key, next_chain)
}
