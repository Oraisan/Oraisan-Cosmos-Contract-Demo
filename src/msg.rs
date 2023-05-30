use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Uint256, Binary};
use std::vec::Vec;

#[cw_serde]
pub struct InstantiateMsg {
    pub token_address: Addr,
    pub root: Uint256,
}

#[cw_serde]
pub struct DepositInfo {
    pub eth_bridge_address: String,
    pub eth_receiver: String
}

#[cw_serde]
pub enum ExecuteMsg {
    Receive {
        sender: Addr,
        amount: Uint128,
        msg: Binary,
    },
    UpdateDepositTree {
        root: Uint256,
        proof: Vec<Uint256>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg 
{   
    #[returns(DepositTreeResponse)]
    DepositTree{},

    #[returns(DepositQueueResponse)]
    DepositQueue{},
}

#[cw_serde]
pub struct DepositTreeResponse {
    pub root: Uint256,
    pub n_leafs: u64,
    pub nqueue_leafs: u64
}

#[cw_serde]
pub struct DepositQueueResponse {
    pub is_deposit: bool,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
    pub amount: Uint128,
    pub cosmos_token_address: Addr,
    pub key: u64,
    pub value: Uint256,
}
