use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{Fp256, QuadExtField};
use ark_groth16::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary, Uint128, Uint256};
use std::str::FromStr;
use std::vec::Vec;
use crate::math:: Uint256 as U256;

#[cw_serde]
pub struct InstantiateMsg {
    pub token_address: Addr,
    pub root: String,
}

#[cw_serde]
pub struct DepositInfo {
    pub destination_chainid: u64,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    SupportTokenPair {
        destination_chainid: u64,
        cosmos_token_address: Addr,
        eth_token_address: String,
    },
    Receive {
        sender: Addr,
        amount: Uint128,
        msg: Binary,
    },
    UpdateDepositTree {
        root: String,
        proof: Vec<Uint256>,
    },
    Withdraw {
        receiver: Addr,
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(DepositTreeResponse)]
    DepositTree {},

    #[returns(DepositTreeResponse)]
    DepositTxsInTree {},

    #[returns(DepositQueueResponse)]
    DepositQueue {},

    #[returns(DepositQueueResponse)]
    TokenPair {
        destination_chainid: u64,
        cosmos_token_address: Addr,
    },
}

#[cw_serde]
pub struct TokenPairResponse {
    pub destination_chainid: u64,
    pub cosmos_token_address: Addr,
    pub eth_token_address: String
}

#[cw_serde]
pub struct DepositTreeResponse {
    pub root: String,
    pub n_leafs: u64,
    pub nqueue_leafs: u64,
}

#[cw_serde]
pub struct DepositQueueResponse {
    pub is_deposit: bool,
    pub sender: Addr,
    pub destination_chainid: u64,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
    pub amount: Uint128,
    pub eth_token_address: String,
    pub cosmos_token_address: Addr,
    pub key: u64,
    pub value: String,
}

#[cw_serde]
pub struct DepositTxsInTreeResponse {
    pub is_deposit: bool,
    pub sender: Addr,
    pub destination_chainid: u64,
    pub eth_bridge_address: String,
    pub eth_receiver: String,
    pub amount: Uint128,
    pub eth_token_address: String,
    pub cosmos_token_address: Addr,
    pub key: u64,
    pub value: String,
}

pub struct PublicSignals(pub Vec<String>);
// Public signals from circom
// public [root, nullifierHash, recipient, relayer, fee]
impl PublicSignals {
    pub fn from(public_signals: Vec<String>) -> Self {
        PublicSignals(public_signals)
    }
    pub fn from_values(key: Vec<u64>, value: Vec<String>, old_root: String, new_root: String) -> Self {
        let mut signals: Vec<String> = Vec::new();
        for i in 0..key.len() {
            signals.push(key[i].to_string());
        }
        
        for i in 0..value.len() {
            signals.push(value[i].to_string());
        }
        signals.push(old_root);
        signals.push(new_root);
        PublicSignals(signals)
    }
    pub fn from_json(public_signals_json: String) -> Self {
        let v: Vec<String> = serde_json::from_str(&public_signals_json).unwrap();
        PublicSignals(v)
    }

    pub fn get(self) -> Vec<Fr> {
        let mut inputs: Vec<Fr> = Vec::new();
        for input in self.0 {
            inputs.push(Fr::from_str(&input).unwrap());
        }
        inputs
    }
}

pub fn uint256_to_bytes_le(x: U256) -> [u8; 32] {
    let mut ans = [0u8; 32];
    let vec = x.to_le_bytes();
    for i in 0..vec.len() {
        ans[i] = vec[i];
    }

    return ans
}

#[cw_serde]
#[serde(rename_all = "camelCase")]
pub struct CircomProof {
    #[serde(rename = "pi_a")]
    pub pi_a: Vec<String>,
    #[serde(rename = "pi_b")]
    pub pi_b: Vec<Vec<String>>,
    #[serde(rename = "pi_c")]
    pub pi_c: Vec<String>,
}

impl CircomProof {
    pub fn from(json_str: String) -> Self {
        serde_json::from_str(&json_str).unwrap()
    }

    pub fn to_proof(self) -> Proof<Bn254> {
        let a = G1Affine::new(
            Fp256::from_str(&self.pi_a[0]).unwrap(),
            Fp256::from_str(&self.pi_a[1]).unwrap(),
            false,
        );
        let b = G2Affine::new(
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[0][0]).unwrap(),
                Fp256::from_str(&self.pi_b[0][1]).unwrap(),
            ),
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[1][0]).unwrap(),
                Fp256::from_str(&self.pi_b[1][1]).unwrap(),
            ),
            false,
        );

        let c = G1Affine::new(
            Fp256::from_str(&self.pi_c[0]).unwrap(),
            Fp256::from_str(&self.pi_c[1]).unwrap(),
            false,
        );
        Proof { a, b, c }
    }
}
