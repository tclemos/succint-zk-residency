# succint-zk-residency

The goal fo the projects is to itnegrate multiples chains/proofs into de aggLayer.

This project have the following proofs:

1. Bridge Proofs: Given a state root of an EVM outputs our bridge information reading the state with static calls
2. OP
    - Consensus: prove optimism root given a open game on L1
    - Chain Proof: Aggregate the bridge proof and consensus proof, linking block hashes
    - More details available [here](./op/README.md)
3. Polygon PoS chain
    - Consensus: Prove that a particular execution layer block has been voted upon by majority (>2/3+1) of the validator set in a modified tendermint consensus
    - Chain Proof: Aggregate the bridge proof and consensus proof, linking block hashes
    - More details available [here](./pos/README.md)
4. Full execution proofs
    - Vanilla clients using local geth running on clique consensus
    - Type 1 proofs
        - Generate block proofs
        - Aggregate multiple block proofs
        - Chain Proof: Aggregate the bridge proof and aggregated block proof, linking block hashes
    - More details available [here](./fep-type-1/README.md)
5. AggLayer proof
    - Aggregates chain-proofs of all the above chains and create a plonk proof to be verified on-chain.

Example of aggregating all this proofs on our current version of the agglayer on sepolia:
https://sepolia.etherscan.io/tx/0xb5cba33c2225e4890072b14e0a94a059d0e5480eab0b74e5b7b2089f2e1ba492