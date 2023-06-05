use ark_bn254::Fr;
use ark_ff::Zero;
use arkworks_mimc::params::mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS};
use arkworks_mimc::{params::round_keys_contants_to_vec, MiMC};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128, WasmMsg,
};
use cw2::set_contract_version;
use std::str::FromStr;
use std::vec::Vec;
use cw20::{self, Cw20ExecuteMsg};

use crate::error::ContractError;
use crate::msg::{
    CircomProof, DepositInfo, DepositQueueResponse, DepositTreeResponse, ExecuteMsg,
    InstantiateMsg, PublicSignals, QueryMsg,
};
use crate::state::{
    BridgeAdmin, DepositQueue, DepositTree, TotalLock, BRIDGE_ADMIN, DEPOSIT_QUEUE, DEPOSIT_TREE,
    TOKEN_LOCK, VERIFIER,
};
use crate::verifier::Verifier;
// use crate::mimc::{Fr, Mimc7};
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:Oraisan-Cosmos-Bridge";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(_deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = BridgeAdmin {
        admin: _info.sender,
    };
    BRIDGE_ADMIN.save(_deps.storage, &admin)?;

    // store token info using cw20-base format
    let data = TotalLock {
        total_lock: Uint128::zero(),
        // set self as minter, so we can properly execute mint and burn
    };

    TOKEN_LOCK.save(_deps.storage, &_msg.token_address, &data)?;

    let deposit_tree = DepositTree {
        root: _msg.root,
        n_leafs: 0,
        nqueue_leafs: 0,
    };

    DEPOSIT_TREE.save(_deps.storage, &deposit_tree)?;

    let verifier = Verifier::new(
        r#"{
    "IC":  [
        [
        "8656539548173846171972495721252578120900824758371923695530671272305370463701",
        "6359677926888595489238489456174024585259362898949274171702028592415924728551",
        "1"
        ],
        [
        "6441980096830165253692634934450314509975464373073592394567213031001635252239",
        "4707522038910469574422274134184910683122728044658829406126231217563062159470",
        "1"
        ],
        [
        "11349172492502164651576992724558217857890858796680916042887894494620313044489",
        "3151261521016136982350172283262617375544742591097187842310583910215551454193",
        "1"
        ],
        [
        "4856135331815648621835540542907934004040815435731265998161481130006732301779",
        "20747905095521196026443797202238170574240840252079423917421350544373352858049",
        "1"
        ],
        [
        "21150891221075894997179193144030633094695774913805159782096033169444666280433",
        "7197484964138085484222812464236963197618894255935942551252404804749069956462",
        "1"
        ],
        [
        "7658653397861975822066661580784436272950214112999928552872486832586260703946",
        "18072816329480057708348267594903894843195535355574050833256185611026804451326",
        "1"
        ],
        [
        "14747051309492185551069255849555119291697355022772452380022771891452434041972",
        "17008634065508961779487252274033159282538506834281162827285694159947097929098",
        "1"
        ],
        [
        "11964433287736363606028419499662814070891197322304152851371407532467685154970",
        "20042338754184369213660587191955217735817843956400142832724495871261696416682",
        "1"
        ],
        [
        "4516654188783066942264093336784237027288602729302280635145928427335354970089",
        "17472708967559971917336532613839610031168216923100860540938560886398570489076",
        "1"
        ],
        [
        "7330648920494009802067733006133584023696593754752127147463570152304880768543",
        "7610374506506286891683621441137596408672758824245113025956128737837274239141",
        "1"
        ],
        [
        "4871971719110680297608269461609124673315228766814673414852886592010108772829",
        "19112141374031784798057788814446471025889818728111032175021155181854827595573",
        "1"
        ],
        [
        "13190889075252673991466805298083608464238934026251732451419032688439562310569",
        "16229107291140034959976780008723302161391518394084328641763669818396930926565",
        "1"
        ],
        [
        "3889290167421440295923815471746069499487853726049557296888790835002891085184",
        "7114039261029582425528395325375216357691773910796669635976029786122380639426",
        "1"
        ]
    ],
    "vk_alfa_1": [
        "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        "1"
    ],
    "vk_alpha_1": [
        "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        "1"
    ],
    "vk_beta_2": [
        [
        "6375614351688725206403948262868962793625744043794305715222011528459656738731",
        "4252822878758300859123897981450591353533073413197771768651442665752259397132"
        ],
        [
        "10505242626370262277552901082094356697409835680220590971873171140371331206856",
        "21847035105528745403288232691147584728191162732299865338377159692350059136679"
        ],
        [
        "1",
        "0"
        ]
    ],
    "vk_gamma_2": [
        [
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "11559732032986387107991004021392285783925812861821192530917403151452391805634"
        ],
        [
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531"
        ],
        [
        "1",
        "0"
        ]
    ],
    "vk_delta_2": [
        [
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "11559732032986387107991004021392285783925812861821192530917403151452391805634"
        ],
        [
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531"
        ],
        [
        "1",
        "0"
        ]
    ],
    "vk_alfabeta_12": [
        [
        [
        "2029413683389138792403550203267699914886160938906632433982220835551125967885",
        "21072700047562757817161031222997517981543347628379360635925549008442030252106"
        ],
        [
        "5940354580057074848093997050200682056184807770593307860589430076672439820312",
        "12156638873931618554171829126792193045421052652279363021382169897324752428276"
        ],
        [
        "7898200236362823042373859371574133993780991612861777490112507062703164551277",
        "7074218545237549455313236346927434013100842096812539264420499035217050630853"
        ]
        ],
        [
        [
        "7077479683546002997211712695946002074877511277312570035766170199895071832130",
        "10093483419865920389913245021038182291233451549023025229112148274109565435465"
        ],
        [
        "4595479056700221319381530156280926371456704509942304414423590385166031118820",
        "19831328484489333784475432780421641293929726139240675179672856274388269393268"
        ],
        [
        "11934129596455521040620786944827826205713621633706285934057045369193958244500",
        "8037395052364110730298837004334506829870972346962140206007064471173334027475"
        ]
        ]
    ],
    "vk_alphabeta_12": [
        [
        [
        "2029413683389138792403550203267699914886160938906632433982220835551125967885",
        "21072700047562757817161031222997517981543347628379360635925549008442030252106"
        ],
        [
        "5940354580057074848093997050200682056184807770593307860589430076672439820312",
        "12156638873931618554171829126792193045421052652279363021382169897324752428276"
        ],
        [
        "7898200236362823042373859371574133993780991612861777490112507062703164551277",
        "7074218545237549455313236346927434013100842096812539264420499035217050630853"
        ]
        ],
        [
        [
        "7077479683546002997211712695946002074877511277312570035766170199895071832130",
        "10093483419865920389913245021038182291233451549023025229112148274109565435465"
        ],
        [
        "4595479056700221319381530156280926371456704509942304414423590385166031118820",
        "19831328484489333784475432780421641293929726139240675179672856274388269393268"
        ],
        [
        "11934129596455521040620786944827826205713621633706285934057045369193958244500",
        "8037395052364110730298837004334506829870972346962140206007064471173334027475"
        ]
        ]
    ],
    "curve": "BN254",
    "protocol": "groth",
    "nPublic": 12
      }"#
        .to_string(),
    );

    VERIFIER.save(_deps.storage, &verifier)?;

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
        ExecuteMsg::UpdateDepositTree { root, proof } => {
            execute_update_deposit_tree(_deps, _env, _info, root, proof)
        }
        ExecuteMsg::Receive {
            sender,
            amount,
            msg,
        } => execute_receive(_deps, _env, _info, sender, amount, msg),
        ExecuteMsg::Withdraw { receiver } => {
            execute_withdraw(_deps, _env, _info, receiver)
        }
    }
}

pub fn execute_withdraw(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    receiver: Addr,
) -> Result<Response, ContractError> {
    let admin = BRIDGE_ADMIN
        .may_load(_deps.storage)?
        .ok_or(ContractError::Unauthorized {})?;
    if admin.admin != _info.sender {
        return Err(ContractError::Unauthorized {});
    }

    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    let from = 0;
    let to = deposit_tree.n_leafs.clone() + deposit_tree.nqueue_leafs.clone();

    for _i in from..to {
        let deposit_transaction = DEPOSIT_QUEUE.load(_deps.storage, _i)?.clone();
        if receiver != deposit_transaction.sender {
            continue;
        }
        transfer_tokens(_info.clone(), deposit_transaction.cosmos_token_address.clone(), deposit_transaction.sender.clone(), deposit_transaction.amount.clone())?;
    }

    Ok(Response::default())
}

// Define a transfer function that sends ERC-20 tokens from Contract A to Receiver B
fn transfer_tokens(
    info: MessageInfo,
    token_contract_address: Addr, // Address of the ERC-20 token contract
    receiver_address: Addr,       // Address of the receiver
    amount: Uint128,                 // Amount of tokens to transfer
) -> StdResult<Response> {
    let transfer_msg = WasmMsg::Execute {
        contract_addr: token_contract_address.clone().to_string(),
        msg: to_binary(&Cw20ExecuteMsg::Transfer {
            recipient: receiver_address.clone().to_string(),
            amount: amount.clone(),
        })?,
        funds: vec![],
    };

    // Send the transfer message to the token contract
    let res = Response::new()
        .add_message(transfer_msg)
        .add_attribute("action", "transfer")
        .add_attribute("sender", info.sender.clone().as_str())
        .add_attribute("recipient", receiver_address.clone().as_str())
        .add_attribute("amount", amount.clone().to_string())
        .add_attribute("token_contract", token_contract_address.clone().as_str());

    Ok(res)
}

pub fn execute_receive(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    sender: Addr,
    amount: Uint128,
    _msg: Binary,
) -> Result<Response, ContractError> {
    // if !(TOKEN_LOCK.may_load(deps.storage, &_info.sender)?).is_some() {
    //     // name is already taken
    //     return Err(ContractError::TokenLock { contract: _info.sender });
    // }

    let deposit_tree: DepositTree = DEPOSIT_TREE.load(_deps.storage)?;
    let key: u64 = deposit_tree.n_leafs.clone() + deposit_tree.nqueue_leafs.clone();

    let deposit_info: DepositInfo = from_binary(&_msg).unwrap();

    let mimc: MiMC<ark_ff::Fp256<ark_bn254::FrParameters>, MIMC_7_91_BN254_PARAMS> =
        MiMC::<Fr, MIMC_7_91_BN254_PARAMS>::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        );

    let value: Vec<ark_ff::Fp256<ark_bn254::FrParameters>> = mimc.permute_non_feistel(vec![
        Fr::from_str(&deposit_info.eth_bridge_address.clone()).unwrap(),
        Fr::from_str(&deposit_info.eth_receiver.clone()).unwrap(),
        Fr::from_str(&amount.clone().to_string()).unwrap(),
        Fr::from_str(_info.sender.clone().as_str()).unwrap(),
    ]);
    DEPOSIT_QUEUE.save(
        _deps.storage,
        key,
        &DepositQueue {
            is_deposit: false,
            sender: sender,
            eth_bridge_address: deposit_info.eth_bridge_address,
            eth_receiver: deposit_info.eth_receiver,
            amount: amount,
            cosmos_token_address: _info.sender,
            key: key,
            value: value[0].to_string(),
        },
    )?;

    DEPOSIT_TREE.update(_deps.storage, |mut tree: DepositTree| -> StdResult<_> {
        tree.nqueue_leafs = deposit_tree.nqueue_leafs.clone() + 1;
        Ok(tree)
    })?;

    Ok(Response::default())
}

pub fn execute_update_deposit_tree(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    root: String,
    proof: CircomProof,
) -> Result<Response, ContractError> {
    let default_value = String::from(
        "11730251359286723731141466095709901450170369094578288842486979042586033922425",
    );
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    let from = deposit_tree.n_leafs.clone();
    let to = deposit_tree.nqueue_leafs.clone();

    let mut new_leafs: Vec<String> = Vec::new();
    let mut key: Vec<u64> = Vec::new();

    for _i in from..5 {
        if _i > to {
            new_leafs.push(default_value.clone());
            continue;
        }

        let deposit_transaction = DEPOSIT_QUEUE.load(_deps.storage, _i)?.clone();

        new_leafs.push(deposit_transaction.value);
        key.push(from.clone() + _i.clone());
    }

    let proof = proof.to_proof();
    let public_signals = PublicSignals::from_values(root.clone(), key, new_leafs);
    let inputs = public_signals.get();

    // 3. Confirm the circuit proof
    let verifier = VERIFIER.load(_deps.storage)?;
    if !verifier.verify_proof(proof, &inputs) {
        return Err(ContractError::InvalidProof {});
    };

    for _i in from..to {
        DEPOSIT_QUEUE.update(_deps.storage, _i, |queue| -> StdResult<_> {
            queue.clone().unwrap().is_deposit = true;
            Ok(queue.unwrap())
        })?;
    }

    DEPOSIT_TREE.update(_deps.storage, |mut tree| -> StdResult<_> {
        tree.root = root.clone();
        tree.n_leafs = from.clone() + to.clone();
        tree.nqueue_leafs = tree.nqueue_leafs.clone() - to.clone();
        Ok(tree)
    })?;

    Ok(Response::default())
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
        nqueue_leafs: deposit_tree.nqueue_leafs,
    };
    Ok(res)
}

fn query_deposit_queue(_deps: Deps) -> StdResult<Vec<DepositQueueResponse>> {
    let mut deposit_queue: Vec<DepositQueueResponse> = Vec::new();
    // let deposit_transaction;
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    for _i in (deposit_tree.n_leafs)..(deposit_tree.nqueue_leafs) {
        let deposit_transaction = DEPOSIT_QUEUE.may_load(_deps.storage, _i)?.unwrap();
        deposit_queue.push(DepositQueueResponse {
            is_deposit: deposit_transaction.is_deposit,
            sender: deposit_transaction.sender,
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
