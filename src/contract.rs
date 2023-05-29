#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, to_binary, from_binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, Uint256};
use std::vec::Vec;
use std::str::FromStr;
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, DepositInfo, QueryMsg, DepositTreeResponse, DepositQueueResponse};
use crate::state::{TotalLock, TOKEN_LOCK, DepositQueue, DEPOSIT_QUEUE, DepositTree, DEPOSIT_TREE};
// use crate::mimc::{Fr, Mimc7};
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:Oraisan-Cosmos-bBridge";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");


#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(_deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // store token info using cw20-base format
    let data = TotalLock {
        total_lock: Uint128::zero(),
        // set self as minter, so we can properly execute mint and burn
    };

    TOKEN_LOCK.save(_deps.storage, &_msg.token_address, &data)?;


    let deposit_tree = DepositTree {
        root: _msg.root,
        n_leafs: 0,
        nqueue_leafs: 0
    };
    
    DEPOSIT_TREE.save(_deps.storage, &deposit_tree)?;
    

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match _msg {
        ExecuteMsg::UpdateDepositTree {root, proof} => execute_update_deposit_tree(_deps, _env, _info, root, proof),
        ExecuteMsg::Receive {
            sender,
            amount,
            msg,
        } => execute_receive(_deps, _env, _info, amount,  msg),
    }
}

pub fn execute_receive(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    amount: Uint128,
    _msg: Binary
) -> Result<Response, ContractError> {

    // if !(TOKEN_LOCK.may_load(deps.storage, &_info.sender)?).is_some() {
    //     // name is already taken
    //     return Err(ContractError::TokenLock { contract: _info.sender });
    // }

    
    let  deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;
    let  key = deposit_tree.n_leafs + deposit_tree.nqueue_leafs;
    
    let deposit_info: DepositInfo = from_binary(&_msg).unwrap();


    DEPOSIT_QUEUE.save(_deps.storage, key, &DepositQueue {
        is_deposit: false,
        eth_bridge_address: deposit_info.eth_bridge_address,
        eth_receiver: deposit_info.eth_receiver,
        amount: amount,
        cosmos_token_address: _info.sender,
        key: key,
        value: deposit_info.value,
    })?;


    DEPOSIT_TREE.update(_deps.storage,|mut tree| -> StdResult<_> {
        tree.nqueue_leafs = deposit_tree.nqueue_leafs + 1;
        Ok(tree)
    })?;

    
    Ok(Response::default())
}


pub fn execute_update_deposit_tree(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    root: Uint256,
    proof: Vec<Uint256>,
) -> Result<Response, ContractError> {
    
    let  default_value = Uint256::from_str("11730251359286723731141466095709901450170369094578288842486979042586033922425").unwrap();
    let  deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;
    let  key = deposit_tree.n_leafs + deposit_tree.nqueue_leafs;

    let from = deposit_tree.n_leafs;
    let mut to = deposit_tree.nqueue_leafs;
    if deposit_tree.nqueue_leafs > 5 {
        to = 5;
    }
    let mut new_leafs: Vec<Uint256> = Vec::new();


    for _i in from..to {
        if _i > deposit_tree.nqueue_leafs {
            new_leafs.push(default_value);
            continue;
        }

        let deposit_transaction =  DEPOSIT_QUEUE.load(_deps.storage, _i)?;
        new_leafs.push(deposit_transaction.value);
    }

    assert!(verifyNewDepositTree(proof, root, new_leafs, deposit_tree.n_leafs));

    for _i in from..to {
        if _i > deposit_tree.nqueue_leafs {
            break;
        }
        
        DEPOSIT_QUEUE.update(_deps.storage, _i, | queue| -> StdResult<_> {
            queue.clone().unwrap().is_deposit = true;
            Ok(queue.unwrap())
        })?;
    }
    
    DEPOSIT_TREE.update(_deps.storage,|mut tree| -> StdResult<_> {
        tree.root = root;
        tree.n_leafs = key;
        tree.nqueue_leafs = tree.nqueue_leafs.clone() - to;
        Ok(tree)
    })?;

    Ok(Response::default())
}

pub fn verifyNewDepositTree(
    proof: Vec<Uint256>,
    root: Uint256,
    new_leafs: Vec<Uint256>,
    start_index: u64
) -> bool {
    let  default_value = Uint256::from_str("11730251359286723731141466095709901450170369094578288842486979042586033922425").unwrap();
    return true;
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    match _msg {
        QueryMsg::DepositTree {} => to_binary(&query_deposit_tree(_deps)?),
        QueryMsg::DepositQueue {} => to_binary(&query_deposit_queue(_deps)?),
    }
}

pub fn query_deposit_tree(deps: Deps) -> StdResult<DepositTreeResponse> {
    let deposit_tree = DEPOSIT_TREE.load(deps.storage)?;
    let res = DepositTreeResponse {
        root: deposit_tree.root,
        n_leafs: deposit_tree.n_leafs,
        nqueue_leafs: deposit_tree.nqueue_leafs
    };
    Ok(res)
}

fn query_deposit_queue(_deps: Deps) -> StdResult<Vec<DepositQueueResponse>> {
    let mut  deposit_queue: Vec<DepositQueueResponse> = Vec::new();
    // let deposit_transaction;
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    for _i in (deposit_tree.n_leafs)..(deposit_tree.nqueue_leafs) {
        let deposit_transaction =  DEPOSIT_QUEUE.may_load(_deps.storage, _i)?.unwrap();
        deposit_queue.push(DepositQueueResponse{
            is_deposit: deposit_transaction.is_deposit,
            eth_bridge_address: deposit_transaction.eth_bridge_address,
            eth_receiver: deposit_transaction.eth_receiver,
            amount: deposit_transaction.amount,
            cosmos_token_address: deposit_transaction.cosmos_token_address,
            key: deposit_transaction.key,
            value: deposit_transaction.value,
        })
    }

    Ok(deposit_queue)
}

#[cfg(test)]
mod tests {}
