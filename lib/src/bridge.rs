use alloy_primitives::{B256, Address};
use sp1_cc_client_executor::io::EVMStateSketch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInput {
    pub l1_ger_addr: Address, // this could be constant
    pub l2_ger_addr: Address, // this could be retrieve fro the Bridge L1 which is constant

    pub injected_gers: Vec<B256>,
    pub injected_ger_count_sketch: EVMStateSketch,
    pub check_injected_gers_and_return_ler_sketch: EVMStateSketch,
    pub check_gers_existance_sketch: EVMStateSketch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeCommit {
    pub prev_l2_block_hash: B256,
    pub new_l2_block_hash: B256,
    pub l1_block_hash: B256,
    pub new_ler: B256,
    pub l1_ger_addr: Address,
    pub l2_ger_addr: Address,
}
