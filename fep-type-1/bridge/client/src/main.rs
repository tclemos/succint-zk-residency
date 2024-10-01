//! A program that verifies the bridge integrity

#![no_main]
sp1_zkvm::entrypoint!(main);

use polccint_lib::{BridgeCommit, BridgeInput};
use sp1_cc_client_executor::{ClientExecutor, ContractInput};
use alloy_sol_types::SolCall;
use alloy_primitives::{address, Address};
use alloy_sol_macro::sol;

sol! (
    function getLastInjectedGER() public view returns (bytes32);
    function checkGERsAreConsecutiveAndReturnLastLER(bytes32 intitialGER, bytes32[] GERs) public view returns (bool, bytes32);
    function checkGERsExistance(bytes32[] calldata GERs) public view returns (bool);
);

/// Address of the caller.
const CALLER: Address = address!("0000000000000000000000000000000000000000");

pub fn main() {
    // Read the input.
    let input = sp1_zkvm::io::read::<BridgeInput>();

    // Verify bridge:
    // 1. Get the the last GER of the previous block on L2
    assert_eq!(input.get_last_injected_ger_l2_prev_block_call.header.hash_slow(), input.prev_l2_block_hash);
    let executor = ClientExecutor::new(input.get_last_injected_ger_l2_prev_block_call).unwrap();
    let get_last_injected_ger_prev_block_input = ContractInput {
        contract_address: input.l2_ger_addr,
        caller_address: CALLER,
        calldata: getLastInjectedGERCall {},
    };
    let get_injected_ger_index_prev_block_call_output = executor.execute(get_last_injected_ger_prev_block_input).unwrap();
    let initial_ger = getLastInjectedGERCall::abi_decode_returns(
        &get_injected_ger_index_prev_block_call_output.contractOutput, 
        false).unwrap()._0;

    // 2. Check that the GERs are consecutive on L2 at the new block
    assert_eq!(input.check_gers_are_consecutive_and_return_last_ler_call_l2_new_block_call.header.hash_slow(), input.new_l2_block_hash);
    let executor: ClientExecutor = ClientExecutor::new(input.check_gers_are_consecutive_and_return_last_ler_call_l2_new_block_call).unwrap();
    let check_gers_consecutiveness_input = ContractInput {
        contract_address: input.l2_ger_addr,
        caller_address: CALLER,
        calldata: checkGERsAreConsecutiveAndReturnLastLERCall { intitialGER: initial_ger, GERs: input.injected_gers.clone()},
    };
    let check_gers_consecutiveness_output = executor.execute(check_gers_consecutiveness_input).unwrap();
    let call_result = checkGERsAreConsecutiveAndReturnLastLERCall::abi_decode_returns(&check_gers_consecutiveness_output.contractOutput, false).unwrap();
    assert_eq!(call_result._0, true);
    assert_eq!(call_result._1, input.new_ler);

    // 3. Check that the GERs exist on L1
    assert_eq!(input.check_gers_existance_l1_call.header.hash_slow(), input.l1_block_hash);
    let executor: ClientExecutor = ClientExecutor::new(input.check_gers_existance_l1_call).unwrap();
    let check_gers_existance_input = ContractInput {
        contract_address: input.l1_ger_addr,
        caller_address: CALLER,
        calldata: checkGERsExistanceCall { GERs: input.injected_gers.clone() },
    };
    let check_gers_existance_call_output = executor.execute(check_gers_existance_input).unwrap();
    let gers_exist = checkGERsExistanceCall::abi_decode_returns(&check_gers_existance_call_output.contractOutput, false).unwrap()._0;
    assert_eq!(gers_exist, true);

    // Commit the bridge proof.
    let bridge_commit = BridgeCommit {
        l1_block_hash: input.l1_block_hash,
        prev_l2_block_hash: input.prev_l2_block_hash,
        new_l2_block_hash: input.new_l2_block_hash,
        new_ler: input.new_ler,
        l1_ger_addr: input.l1_ger_addr,
        l2_ger_addr: input.l2_ger_addr,
    };   
    sp1_zkvm::io::commit(&bridge_commit);
}
