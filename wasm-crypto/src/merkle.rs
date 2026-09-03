//! Merkle trees: one hash that commits to many records.
//!
//! Leaves are hashed with a 0x00 prefix and interior nodes with 0x01 (the
//! domain separation from RFC 6962, which stops a leaf masquerading as a
//! node); an odd node at the end of a level is promoted unchanged. Any single
//! record can then be proved present with log₂(n) hashes — the mechanism
//! behind Certificate Transparency logs, Bitcoin's SPV proofs, and binary
//! transparency for software updates.

use crate::{CryptoError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const MAX_LEAVES: usize = 64;

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn split_leaves(text: &str) -> Result<Vec<&str>> {
    let leaves: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if leaves.is_empty() {
        return Err(CryptoError::new("Enter at least one record, one per line"));
    }
    if leaves.len() > MAX_LEAVES {
        return Err(CryptoError::new(format!("At most {MAX_LEAVES} records")));
    }
    Ok(leaves)
}

fn build_levels(leaves: &[&str]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves.iter().map(|l| leaf_hash(l.as_bytes())).collect::<Vec<_>>()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::new();
        for pair in prev.chunks(2) {
            // A lone node at the end of a level is promoted unchanged.
            next.push(if pair.len() == 2 { node_hash(&pair[0], &pair[1]) } else { pair[0] });
        }
        levels.push(next);
    }
    levels
}

#[derive(Serialize)]
pub struct MerkleTree {
    /// Level 0 = leaf hashes, last level = [root]; hex.
    pub levels: Vec<Vec<String>>,
    pub root: String,
    pub leaves: u32,
    pub proof_length: u32,
}

pub fn merkle_tree(text: &str) -> Result<MerkleTree> {
    let leaves = split_leaves(text)?;
    let levels = build_levels(&leaves);
    let root = hex::encode(levels.last().unwrap()[0]);
    Ok(MerkleTree {
        root,
        leaves: leaves.len() as u32,
        proof_length: (levels.len() - 1) as u32,
        levels: levels.iter().map(|lv| lv.iter().map(hex::encode).collect()).collect(),
    })
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofStep {
    pub sibling: String,
    /// Whether the sibling sits to the right of the running hash.
    pub right: bool,
}

#[derive(Serialize)]
pub struct MerkleProof {
    pub index: u32,
    pub leaf: String,
    pub leaf_hash: String,
    pub steps: Vec<ProofStep>,
    pub root: String,
}

pub fn merkle_proof(text: &str, index: u32) -> Result<MerkleProof> {
    let leaves = split_leaves(text)?;
    let i = index as usize;
    if i >= leaves.len() {
        return Err(CryptoError::new(format!("Index {index} is out of range (0–{})", leaves.len() - 1)));
    }
    let levels = build_levels(&leaves);
    let mut steps = Vec::new();
    let mut pos = i;
    for level in &levels[..levels.len() - 1] {
        let sib = if pos.is_multiple_of(2) { pos + 1 } else { pos - 1 };
        if sib < level.len() {
            steps.push(ProofStep { sibling: hex::encode(level[sib]), right: sib > pos });
        }
        pos /= 2;
    }
    Ok(MerkleProof {
        index,
        leaf: leaves[i].to_string(),
        leaf_hash: hex::encode(leaf_hash(leaves[i].as_bytes())),
        steps,
        root: hex::encode(levels.last().unwrap()[0]),
    })
}

#[derive(Serialize)]
pub struct MerkleVerify {
    pub computed_root: String,
    pub matches: bool,
    /// The running hash after each combining step.
    pub trail: Vec<String>,
}

/// Recompute the root from a leaf and its proof — all a verifier ever needs.
pub fn merkle_verify(leaf: &str, steps: &[ProofStep], expected_root: &str) -> Result<MerkleVerify> {
    let mut acc = leaf_hash(leaf.as_bytes());
    let mut trail = vec![hex::encode(acc)];
    for step in steps {
        let sib: [u8; 32] = hex::decode(&step.sibling)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| CryptoError::new("A proof step is not a 32-byte hex hash"))?;
        acc = if step.right { node_hash(&acc, &sib) } else { node_hash(&sib, &acc) };
        trail.push(hex::encode(acc));
    }
    let computed_root = hex::encode(acc);
    Ok(MerkleVerify { matches: computed_root == expected_root.trim().to_lowercase(), computed_root, trail })
}

#[wasm_bindgen]
pub struct Merkle;

#[wasm_bindgen]
impl Merkle {
    pub fn tree(records: &str) -> Result<JsValue> {
        to_js(&merkle_tree(records)?)
    }
    pub fn proof(records: &str, index: u32) -> Result<JsValue> {
        to_js(&merkle_proof(records, index)?)
    }
    /// `steps` round-trips the ProofStep array from `proof`.
    pub fn verify(leaf: &str, steps: JsValue, expected_root: &str) -> Result<JsValue> {
        let steps: Vec<ProofStep> = serde_wasm_bindgen::from_value(steps)
            .map_err(|e| CryptoError::new(e.to_string()))?;
        to_js(&merkle_verify(leaf, &steps, expected_root)?)
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| CryptoError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_trees_match_an_independent_construction() {
        // One leaf: the root IS the 0x00-prefixed leaf hash.
        let one = merkle_tree("alice pays bob 5").unwrap();
        let mut h = Sha256::new();
        h.update([0u8]);
        h.update(b"alice pays bob 5");
        assert_eq!(one.root, hex::encode(h.finalize()));
        assert_eq!(one.proof_length, 0);

        // Two leaves: H(01 ‖ H(00‖a) ‖ H(00‖b)), built here by hand.
        let two = merkle_tree("a\nb").unwrap();
        let (la, lb) = (leaf_hash(b"a"), leaf_hash(b"b"));
        let mut h = Sha256::new();
        h.update([1u8]);
        h.update(la);
        h.update(lb);
        assert_eq!(two.root, hex::encode(h.finalize()));

        // Three leaves: the odd leaf is promoted, root = H(01 ‖ H(01‖la‖lb) ‖ lc).
        let three = merkle_tree("a\nb\nc").unwrap();
        let expected = node_hash(&node_hash(&la, &lb), &leaf_hash(b"c"));
        assert_eq!(three.root, hex::encode(expected));
        assert_eq!(three.levels.len(), 3);
    }

    #[test]
    fn every_leaf_of_every_size_proves_and_verifies() {
        for n in 1..=9usize {
            let records: Vec<String> = (0..n).map(|i| format!("record {i}")).collect();
            let text = records.join("\n");
            let tree = merkle_tree(&text).unwrap();
            for i in 0..n {
                let proof = merkle_proof(&text, i as u32).unwrap();
                let v = merkle_verify(&proof.leaf, &proof.steps, &tree.root).unwrap();
                assert!(v.matches, "n = {n}, leaf {i}");
                // A tampered record fails against the same proof and root.
                let bad = merkle_verify("record 99", &proof.steps, &tree.root).unwrap();
                assert!(!bad.matches);
            }
        }
        assert!(merkle_proof("a\nb", 2).is_err());
        assert!(merkle_tree("\n\n").is_err());
    }

    #[test]
    fn domain_separation_keeps_leaves_and_nodes_apart() {
        // Without the 0x00/0x01 prefixes, a crafted 64-byte "record" equal to
        // two leaf hashes would collide with an interior node. With them, the
        // same bytes hash differently as leaf and as node.
        let (la, lb) = (leaf_hash(b"a"), leaf_hash(b"b"));
        let mut concat = Vec::new();
        concat.extend_from_slice(&la);
        concat.extend_from_slice(&lb);
        assert_ne!(leaf_hash(&concat), node_hash(&la, &lb));
    }
}
