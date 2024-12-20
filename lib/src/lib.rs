use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

pub mod bridge;
pub mod constants;
pub mod fep_type_1;
pub mod op;
pub mod pos;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProof {
    pub prev_l2_block_hash: B256,
    pub new_l2_block_hash: B256,
    pub l1_block_hash: B256,
    pub new_ler: B256,
    pub l1_ger_addr: Address,
    pub l2_ger_addr: Address,
    pub consensus_hash: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggLayerProofInput {
    pub chain_proofs: Vec<ChainProof>,
    pub vks: Vec<[u32; 8]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggLayerProofCommit {
    pub chain_proofs: Vec<ChainProof>,
}

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct ChainProofSolidity {
        bytes32 prev_l2_block_hash;
        bytes32 new_l2_block_hash;
        bytes32 l1_block_hash;
        bytes32 new_ler;
        address l1_ger_addr;
        address l2_ger_addr;
        bytes32 consensus_hash;
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct AggLayerProofSolidity {
        ChainProofSolidity[] chain_proofs;
    }
}
