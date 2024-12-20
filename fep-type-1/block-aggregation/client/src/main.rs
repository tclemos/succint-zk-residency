//! A program that aggregates the proofs of EVM blocks

#![no_main]
sp1_zkvm::entrypoint!(main);

use polccint_lib::fep_type_1::{BlockAggregationCommit, BlockAggregationInput};
use polccint_lib::constants::BLOCK_VK;

use sha2::{Digest,Sha256};
use bincode;

pub fn main() {
    // Read the input.

    // could pass just an array of blockhashes
    let input = sp1_zkvm::io::read::<BlockAggregationInput>();

    // Confirm that the blocks are sequential.
    assert!(!input.block_commits.is_empty());

    input.block_commits.windows(2).for_each(|pair| {
        let (prev_block, block) = (&pair[0], &pair[1]);
        assert_eq!(prev_block.new_block_hash, block.prev_block_hash);
    });

    // Verify the block proofs.
    for i in 0..input.block_commits.len() {
        let public_values = &input.block_commits[i];
        let serialized_public_values = bincode::serialize(public_values).unwrap();
        let public_values_digest = Sha256::digest(serialized_public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(&BLOCK_VK, &public_values_digest.into());
    }

    // Commit the block aggregation proof.
    let block_aggregation_commit = BlockAggregationCommit {
        prev_l2_block_hash: input.block_commits[0].prev_block_hash,
        new_l2_block_hash: input.block_commits.last().unwrap().new_block_hash,
    };
    sp1_zkvm::io::commit(&block_aggregation_commit);
}
