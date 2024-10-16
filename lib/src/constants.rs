use alloy_primitives::{address, Address};

// final aggregation vk: 0x00c7dca51c03c7b4db25b4c342d4178b8e7e1107dbcbf246c372a91c2950a068

/// Address of the caller.
pub const CALLER_L1: Address = address!("0000000000000000000000000000000000000000");
pub const CALLER: Address = address!("0000000000000000000000000000000000000000");

pub const BLOCK_VK: [u32; 8] = [1280180439, 306164315, 280359417, 972354760, 1696891725, 921746366, 380532814, 247570928];

pub const BRIDGE_VK: [u32; 8] = [293708904, 1518261052, 1706628892, 1761769297, 143066005, 1734283536, 1795652438, 1400207735];
// aggregation vk
pub const AGGREGATION_VK: [u32; 8] = [1386211125, 1333097880, 1613322187, 98962433, 199655472, 1432683052, 1679920461, 1774600853];

pub const OP_CONSENSUS_VK: [u32; 8] = [148134805, 1166353123, 972167095, 1131577129, 1223163764, 508550116, 475408734, 1785553195]; // TODO: add correct vkey
pub const CHAIN_VK: [u32; 8] = [219277349, 376617125, 1259615231, 1224835443, 1945667762, 1915989897, 699847544, 1199127966];


