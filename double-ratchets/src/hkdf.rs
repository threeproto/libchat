use hkdf::Hkdf;
use sha2::Sha256;

const DOMAIN_ROOT: &[u8] = b"DoubleRatchetRootKey";

/// Derive a new root key and chain key from the given root key and Diffie-Hellman shared secret.
///
/// # Arguments
///
/// * `root` - The current root key.
/// * `dh` - The Diffie-Hellman shared secret.
///
/// # Returns
///
/// A tuple containing the new root key and chain key.
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

/// Derive a new chain key from the given chain key.
///
/// # Arguments
///
/// * `chain` - The current chain key.
///
/// # Returns
///
/// A tuple containing the new chain key and message key.
pub fn kdf_chain(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, chain);

    let mut msg_key = [0u8; 32];
    let mut next_chain = [0u8; 32];

    hk.expand(&[0x01], &mut msg_key).unwrap();
    hk.expand(&[0x02], &mut next_chain).unwrap();

    (next_chain, msg_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_root_deterministic_output() {
        // Fixed inputs for reproducible testing
        let root = [0x11; 32];
        let dh = [0x22; 32];

        let (new_root, chain) = kdf_root(&root, &dh);

        // These values can be verified manually or against a reference implementation
        // (e.g., Signal's spec or another HKDF test vector)
        let expected_new_root = [
            152, 174, 116, 228, 200, 114, 21, 84, 196, 120, 145, 179, 10, 10, 144, 210, 194, 240,
            189, 98, 49, 186, 171, 200, 19, 33, 99, 59, 69, 203, 110, 66,
        ];
        let expected_chain = [
            39, 65, 67, 158, 63, 149, 175, 55, 243, 225, 9, 76, 181, 129, 202, 54, 48, 40, 74, 79,
            53, 179, 41, 49, 70, 178, 185, 81, 163, 16, 197, 160,
        ];

        assert_eq!(new_root, expected_new_root);
        assert_eq!(chain, expected_chain);

        // Run again to ensure determinism
        let (new_root2, chain2) = kdf_root(&root, &dh);
        assert_eq!(new_root, new_root2);
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_kdf_chain_sequence() {
        let initial_chain = [0xaa; 32];

        let (msg_key1, chain2) = kdf_chain(&initial_chain);
        let (msg_key2, chain3) = kdf_chain(&chain2);
        let (msg_key3, chain4) = kdf_chain(&chain3);

        // All message keys should be different
        assert_ne!(msg_key1, msg_key2);
        assert_ne!(msg_key2, msg_key3);
        assert_ne!(msg_key1, msg_key3);

        // Chain keys should evolve
        assert_ne!(initial_chain, chain2);
        assert_ne!(chain2, chain3);
        assert_ne!(chain3, chain4);
    }

    #[test]
    fn test_kdf_chain_deterministic() {
        let chain = [0xff; 32];

        let (next_chain, msg_key) = kdf_chain(&chain);

        let expected_msg_key = [
            59, 94, 15, 96, 71, 100, 166, 72, 61, 235, 228, 226, 68, 254, 106, 30, 142, 34, 35,
            190, 189, 234, 179, 119, 16, 104, 72, 22, 35, 124, 11, 121,
        ];
        let expected_next_chain = [
            99, 67, 0, 116, 62, 113, 20, 228, 182, 63, 203, 83, 138, 72, 123, 175, 3, 173, 108,
            219, 164, 226, 95, 144, 22, 234, 166, 190, 160, 116, 78, 106,
        ];

        assert_eq!(msg_key, expected_msg_key);
        assert_eq!(next_chain, expected_next_chain);
    }

    #[test]
    fn test_full_ratchet_step() {
        // Simulate one full root update + chain step
        let root = [0x01; 32];
        let dh_out = [0x02; 32];

        let (new_root, sending_chain) = kdf_root(&root, &dh_out);

        let (msg_key, next_chain) = kdf_chain(&sending_chain);

        // All outputs should be cryptographically distinct and non-zero
        assert_ne!(new_root, root);
        assert_ne!(sending_chain, [0u8; 32]);
        assert_ne!(msg_key, [0u8; 32]);
        assert_ne!(next_chain, sending_chain);

        // Message key should not leak chain key info
        assert_ne!(msg_key, sending_chain);
        assert_ne!(msg_key, next_chain);
    }

    #[test]
    fn test_different_inputs_produce_different_outputs() {
        let root1 = [0x11; 32];
        let root2 = [0x11; 32];
        let mut root2_modified = root2;
        root2_modified[0] ^= 0x01;

        let dh1 = [0x22; 32];
        let dh2 = [0x22; 32];
        let mut dh2_modified = dh2;
        dh2_modified[31] ^= 0x80;

        let (out1, _) = kdf_root(&root1, &dh1);
        let (out2, _) = kdf_root(&root2_modified, &dh1);
        let (out3, _) = kdf_root(&root1, &dh2_modified);

        assert_ne!(out1, out2); // Changing root changes output
        assert_ne!(out1, out3); // Changing DH changes output
    }
}
