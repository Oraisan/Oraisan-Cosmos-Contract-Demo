use crate::math::Uint256 as U256;
use crate::poseidon::Poseidon;
use crate::{msg::uint256_to_bytes_le, verifier::Verifier};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use std::str::FromStr;
use std::vec::Vec;

#[cw_serde]
pub struct BridgeAdmin {
    pub admin: Addr,
}

#[cw_serde]
#[derive(Default)]
pub struct DepositTree {
    pub root: String,
    pub n_leafs: u64,
    pub nqueue_leafs: u64,
}

#[cw_serde]
pub struct TotalLock {
    pub total_lock: Uint128,
}
#[cw_serde]
pub struct DepositQueue {
    // pub cosmos_chainid: Uint128,
    // pub eth_chainid: Uint128,
    pub is_deposit: bool,
    pub sender: Addr,
    pub destination_chainid: u64,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
    pub amount: Uint128,
    pub cosmos_token_address: Addr,
    pub key: u64,
    pub value: String,
}

pub fn get_hash(inputs: Vec<String>) -> String {
    let poseidon = Poseidon::new();

    let mut inputs_bytes: Vec<[u8; 32]> = vec![];
    for i in 0..inputs.len() {
        inputs_bytes.push(uint256_to_bytes_le(U256::from_str(&inputs.get(i).unwrap()).unwrap()));
    }
    // let inputs_bytes = vec![uint256_to_bytes_le(destination_chainid), uint256_to_bytes_le(eth_bridge_address), uint256_to_bytes_le(eth_receiver), uint256_to_bytes_le(amount)];
    
    let res = poseidon.hash(inputs_bytes).unwrap();

    println!("Hash {}", U256::from_le_bytes(res.clone()).to_string());
    U256::from_le_bytes(res).to_string()
}

pub const BRIDGE_ADMIN: Item<BridgeAdmin> = Item::new("bridge_admin");
pub const TOKEN_LOCK: Map<&Addr, TotalLock> = Map::new("token_lock");
pub const DEPOSIT_QUEUE: Map<u64, DepositQueue> = Map::new("deposit_queue");
pub const DEPOSIT_TREE: Item<DepositTree> = Item::new("deposit_tree");
pub const VERIFIER: Item<Verifier> = Item::new("verifier");
pub const TOKEN_PAIR: Map<(u64, &Addr), String> = Map::new("token_pair");
