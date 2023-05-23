use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128, Uint256};
use cw_storage_plus::{Item, Map};
// use crate::mimc::{Fr};
// extern crate ff;
// use ff::*;
/// Supply is dynamic and tracks the current supply of staked and ERC20 tokens.
#[cw_serde]
#[derive(Default)]
pub struct DepositTree {
    pub root: Uint256,
    pub n_leafs: u64,
    pub nqueue_leafs: u64
}

#[cw_serde]
pub struct TotalLock {
    pub total_lock: Uint128
}
#[cw_serde]
pub struct DepositQueue {
    // pub cosmos_chainid: Uint128,
    // pub eth_chainid: Uint128,
    pub is_deposit: bool,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
    pub amount: Uint128,
    pub cosmos_token_address: Addr,
    pub key: u64,
    pub value: Uint256,
}

pub const TOKEN_LOCK: Map<&Addr, TotalLock> = Map::new("token_lock");
pub const DEPOSIT_QUEUE: Map<u64, DepositQueue> = Map::new("deposit_queue");
pub const DEPOSIT_TREE: Item<DepositTree> = Item::new("deposit_tree");
