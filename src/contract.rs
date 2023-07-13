#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128, Uint256, WasmMsg,
};
use cw2::set_contract_version;
use cw20::{self, Cw20ExecuteMsg};
// use ff::hex::FromHex;
// use std::str::FromStr;
use std::vec::Vec;
// use bigint::U256;

use crate::error::ContractError;
use crate::msg::{
    CircomProof, DepositInfo, DepositQueueResponse, DepositTreeResponse, DepositTxsInTreeResponse,
    ExecuteMsg, InstantiateMsg, PublicSignals, QueryMsg, TokenPairResponse,
};
use crate::state::{
    get_hash, BridgeAdmin, DepositQueue, DepositTree, TotalLock, BRIDGE_ADMIN, DEPOSIT_QUEUE,
    DEPOSIT_TREE, TOKEN_LOCK, TOKEN_PAIR, VERIFIER,
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
            "IC": [
            [
            "20888369345099474436789168374274050305142301447724861882220519354996817723845",
            "18309077993433377444567250667643914406905938478044996980309846305463398484449",
            "1"
            ],
            [
            "13194631598893577588266361050470805069651234679602643397809268752088193812111",
            "11269033304553446435250842751483993523237556399345274935236222088259086493212",
            "1"
            ],
            [
            "19437496248786598097676258150508367695708525237914766627794915570333814191277",
            "14755683362180370324198684885930893605443300384728472902759908168785442098767",
            "1"
            ],
            [
            "7351105406995617578485949572635954531713553182656297808732235022032598890391",
            "10795845324454540435487975239392684238772069396674733619456089581438274784719",
            "1"
            ],
            [
            "486079083671251961029972645307560004978341263112552101319692091802143785232",
            "11567033724676380145492181129731119841148676271461320605113841245919709764947",
            "1"
            ],
            [
            "20835372074433296972292685634771179097802559615421258812812392464142182902392",
            "2811300129615980218219811972679259982649422648798528155653227873390886351926",
            "1"
            ],
            [
            "2322644635050950400979819609321873256879832162143472236627645118540954891556",
            "13765930788340254156968456061867183563465664706205616827718179720170405676736",
            "1"
            ],
            [
            "16859698992047127853264526958672791415974771053562341571476903330690743907624",
            "20010450862670097607731978969089697723936694503651371019108095627412908470296",
            "1"
            ],
            [
            "21844512681749303214175952632415971163200710905460283052497910979065648101616",
            "8340982314498350152384951401758857479656049658674834257869376081094550261305",
            "1"
            ],
            [
            "3586686021462399999997640942044265200323371157397504689637223046331989859187",
            "3336205142667604934712806833427236488305383278641553936962099050575924735924",
            "1"
            ],
            [
            "15781254800408551685412323833953701020685473255744642321908957289192930056429",
            "20227158851907288399803634729124747495385519645573329039153797825683539252549",
            "1"
            ],
            [
            "6660585883207311044882083000256592726362929804602353187306560426919183928485",
            "16976182484978911848203878292867492926849848891980091244756068599066205540487",
            "1"
            ],
            [
            "8659867534047006475854046211919368779708017253980201266355905103040073584914",
            "6744115467407907759324847686864362425039347282092813262547763617004528682437",
            "1"
            ]
            ]
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
        ExecuteMsg::SupportTokenPair {
            destination_chainid,
            cosmos_token_address,
            eth_token_address,
        } => execute_support_token_pair(
            _deps,
            _env,
            _info,
            destination_chainid,
            cosmos_token_address,
            eth_token_address,
        ),
        ExecuteMsg::UpdateDepositTree { root, proof } => {
            execute_update_deposit_tree(_deps, _env, _info, root, proof)
        }
        ExecuteMsg::Receive {
            sender,
            amount,
            msg,
        } => execute_receive(_deps, _env, _info, sender, amount, msg),
        ExecuteMsg::Withdraw { receiver } => execute_withdraw(_deps, _env, _info, receiver),
    }
}

pub fn execute_support_token_pair(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    destination_chainid: u64,
    cosmos_token_address: Addr,
    eth_token_address: String,
) -> Result<Response, ContractError> {
    let admin = BRIDGE_ADMIN
        .may_load(_deps.storage)?
        .ok_or(ContractError::Unauthorized {})?;
    if admin.admin != _info.sender {
        return Err(ContractError::Unauthorized {});
    }

    TOKEN_PAIR.save(
        _deps.storage,
        (destination_chainid, &cosmos_token_address),
        &eth_token_address,
    )?;
    Ok(Response::default())
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
        transfer_tokens(
            _info.clone(),
            deposit_transaction.cosmos_token_address.clone(),
            deposit_transaction.sender.clone(),
            deposit_transaction.amount.clone(),
        )?;
    }

    Ok(Response::default())
}

// Define a transfer function that sends ERC-20 tokens from Contract A to Receiver B
fn transfer_tokens(
    info: MessageInfo,
    token_contract_address: Addr, // Address of the ERC-20 token contract
    receiver_address: Addr,       // Address of the receiver
    amount: Uint128,              // Amount of tokens to transfer
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

    let eth_token_address: String = TOKEN_PAIR.load(
        _deps.storage,
        (
            deposit_info.destination_chainid.clone(),
            &_info.sender.clone(),
        ),
    )?;
    let mut inputs: Vec<String> = vec![];
    inputs.push(deposit_info.eth_bridge_address.clone());
    inputs.push(deposit_info.eth_receiver.clone());
    inputs.push(amount.clone().to_string());
    inputs.push(eth_token_address.clone());
    // let mimc: MiMC<ark_ff::Fp256<ark_bn254::FrParameters>, MIMC_7_91_BN254_PARAMS> =
    //     MiMC::<Fr, MIMC_7_91_BN254_PARAMS>::new(
    //         1,
    //         Fr::zero(),
    //         round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
    //     );

    // let value: Vec<ark_ff::Fp256<ark_bn254::FrParameters>> = mimc.permute_non_feistel(vec![
    //     Fr::from_str(&deposit_info.eth_bridge_address.clone()).unwrap(),
    //     Fr::from_str(&deposit_info.eth_receiver.clone()).unwrap(),
    //     Fr::from_str(&amount.clone().to_string()).unwrap(),
    //     Fr::from_str("68773751032711639832818702821433578180463592946098407213130584708186862886400").unwrap(),
    // ]);
    DEPOSIT_QUEUE.save(
        _deps.storage,
        key,
        &DepositQueue {
            is_deposit: false,
            sender: sender,
            destination_chainid: deposit_info.destination_chainid,
            eth_bridge_address: deposit_info.eth_bridge_address,
            eth_receiver: deposit_info.eth_receiver,
            amount: amount,
            cosmos_token_address: _info.sender,
            key: key,
            value: get_hash(inputs),
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
    proof: Vec<Uint256>,
) -> Result<Response, ContractError> {
    let default_value = String::from(
        "19014214495641488759237505126948346942972912379615652741039992445865937985820",
    );
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    let from = deposit_tree.n_leafs.clone();
    let to = deposit_tree.nqueue_leafs.clone();

    let mut new_leafs: Vec<String> = Vec::new();
    let mut key: Vec<u64> = Vec::new();
    for _i in from..5 {

        key.push(from.clone() + _i.clone());
        if _i >= to {
            new_leafs.push(default_value.clone());
            continue;
        } else {
            let deposit_transaction = DEPOSIT_QUEUE.load(_deps.storage, _i.clone())?.clone();
    
            new_leafs.push(deposit_transaction.value);
        }
    }

    let circom_proof = CircomProof {
        pi_a: vec![proof[0].to_string(), proof[1].to_string()],
        pi_b: vec![
            vec![proof[2].to_string(), proof[3].to_string()],
            vec![proof[4].to_string(), proof[5].to_string()],
        ],
        pi_c: vec![proof[6].to_string(), proof[7].to_string()],
    };

    let _proof = circom_proof.to_proof();
    let public_signals =
        PublicSignals::from_values(key, new_leafs, deposit_tree.root.clone(), root.clone());
    let inputs = public_signals.get();
    // 3. Confirm the circuit proof
    let verifier = VERIFIER.load(_deps.storage)?;
    if !verifier.verify_proof(_proof, &inputs) {
        return Err(ContractError::InvalidProof {});
    };
    for _i in from..to {
        DEPOSIT_QUEUE.update(_deps.storage, _i.clone(), |queue| {
            if let Some(mut queue) = queue {
                queue.is_deposit = true;
                Ok(queue)
            } else {
                Err(ContractError::Unauthorized {})
            }
        })?;
    }
    println!("Verify proof 3");
    DEPOSIT_TREE.update(_deps.storage, |mut tree: DepositTree| -> StdResult<_> {
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
        QueryMsg::TokenPair {
            destination_chainid,
            cosmos_token_address,
        } => to_binary(&query_token_pair(
            _deps,
            destination_chainid,
            cosmos_token_address,
        )?),
        QueryMsg::DepositTxsInTree {} => to_binary(&query_deposit_txs_in_tree(_deps)?),
    }
}

pub fn query_token_pair(
    deps: Deps,
    destination_chainid: u64,
    cosmos_token_address: Addr,
) -> StdResult<TokenPairResponse> {
    let eth_token_address = TOKEN_PAIR.load(
        deps.storage,
        (destination_chainid.clone(), &cosmos_token_address.clone()),
    )?;
    let res = TokenPairResponse {
        destination_chainid: destination_chainid,
        cosmos_token_address: cosmos_token_address,
        eth_token_address: eth_token_address,
    };
    Ok(res)
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

fn query_deposit_txs_in_tree(_deps: Deps) -> StdResult<Vec<DepositTxsInTreeResponse>> {
    let mut deposit_queue: Vec<DepositTxsInTreeResponse> = Vec::new();
    // let deposit_transaction;
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    
    for _i in 0..(deposit_tree.n_leafs) {
        let deposit_transaction = DEPOSIT_QUEUE.may_load(_deps.storage, _i)?.unwrap();
        let eth_token_address = TOKEN_PAIR.load(
            _deps.storage,
            (deposit_transaction.destination_chainid.clone(), &deposit_transaction.cosmos_token_address.clone()),
        )?;
        deposit_queue.push(DepositTxsInTreeResponse {
            is_deposit: deposit_transaction.is_deposit,
            sender: deposit_transaction.sender,
            destination_chainid: deposit_transaction.destination_chainid,
            eth_bridge_address: deposit_transaction.eth_bridge_address,
            eth_receiver: deposit_transaction.eth_receiver,
            amount: deposit_transaction.amount,
            eth_token_address: eth_token_address,
            cosmos_token_address: deposit_transaction.cosmos_token_address,
            key: deposit_transaction.key,
            value: deposit_transaction.value,
        })
    }

    Ok(deposit_queue)
}

fn query_deposit_queue(_deps: Deps) -> StdResult<Vec<DepositQueueResponse>> {
    let mut deposit_queue: Vec<DepositQueueResponse> = Vec::new();
    // let deposit_transaction;
    let deposit_tree = DEPOSIT_TREE.load(_deps.storage)?;

    for _i in (deposit_tree.n_leafs)..(deposit_tree.nqueue_leafs) {
        let deposit_transaction = DEPOSIT_QUEUE.may_load(_deps.storage, _i)?.unwrap();
        let eth_token_address = TOKEN_PAIR.load(
            _deps.storage,
            (deposit_transaction.destination_chainid.clone(), &deposit_transaction.cosmos_token_address.clone()),
        )?;
        deposit_queue.push(DepositQueueResponse {
            is_deposit: deposit_transaction.is_deposit,
            sender: deposit_transaction.sender,
            destination_chainid: deposit_transaction.destination_chainid,
            eth_bridge_address: deposit_transaction.eth_bridge_address,
            eth_receiver: deposit_transaction.eth_receiver,
            amount: deposit_transaction.amount,
            eth_token_address: eth_token_address,
            cosmos_token_address: deposit_transaction.cosmos_token_address,
            key: deposit_transaction.key,
            value: deposit_transaction.value,
        })
    }

    Ok(deposit_queue)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        to_binary, Uint128, Uint256,
    };

    use crate::{
        msg::{CircomProof, DepositInfo, ExecuteMsg, InstantiateMsg, PublicSignals},
        state::get_hash,
        verifier::Verifier,
    };

    use super::{execute, instantiate};

    #[test]
    fn test_receive_token() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("ADDR1", &vec![]);
        // Instantiate the contract
        let msg = InstantiateMsg {
            token_address: info.sender.clone(),
            root: "11725352275130973532665246471810130191684985477615997572384835458693213713650"
                .to_string(),
        };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::SupportTokenPair {
            destination_chainid: 97,
            cosmos_token_address: info.sender.clone(),
            eth_token_address: "1319061186842128966203187681337397035350251722050".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg_bridge = DepositInfo {
            destination_chainid: 97,
            eth_bridge_address: "815392982745749520107554614631753406046346802774".to_string(),
            eth_receiver: "655825492017449793452124397016956580461783097376".to_string(),
        };

        let msg = ExecuteMsg::Receive {
            sender: info.sender.clone(),
            amount: Uint128::from(10u128),
            msg: to_binary(&msg_bridge.clone()).unwrap(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::UpdateDepositTree {
            root: "15665974914820244658079196066615423965698373320063142844458658654091088310782"
                .to_string(),
            proof: vec![
                Uint256::from_str(
                    "10045425106814620998108609111011310373969209290861006180907706539847613743509",
                )
                .unwrap(),
                Uint256::from_str(
                    "718152540660883928665326863557780929986193310783059393518150462362147865847",
                )
                .unwrap(),
                Uint256::from_str(
                    "6012186038133569193278988244098456297019419505085326372174798797512439632444",
                )
                .unwrap(),
                Uint256::from_str(
                    "10433872248993714486794977647678966239075952039825324376129453728297054361153",
                )
                .unwrap(),
                Uint256::from_str(
                    "3250158758054476810230476431604780794693462676099495150439743148422972363911",
                )
                .unwrap(),
                Uint256::from_str(
                    "15552911574665944368995574570313891333645134320413912551779897279122431000402",
                )
                .unwrap(),
                Uint256::from_str(
                    "6707769147098806327505857424871181579319436909753467680253044747679417388367",
                )
                .unwrap(),
                Uint256::from_str(
                    "4486763076427135600522023109971430304310328122478446962286253986798947471413",
                )
                .unwrap(),
            ],
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
    }

    #[test]
    fn test_get_hash() {
        let mut inputs = vec![];
        inputs.push("587642314958878643560627341163159426040011073183".to_string());
        inputs.push("655825492017449793452124397016956580461783097376".to_string());
        inputs.push(Uint128::from(10u128).to_string());
        inputs.push("587642314958878643560627341163159426040011073183".to_string());
        let hash: String = get_hash(inputs);
        println!("hash {}", hash);
    }

    #[test]
    fn test_verify_proof() {
        let circom_proof = CircomProof {
            pi_a: vec![
                "19234271727999268848245608089119920574210821606734014063284268876523819758064"
                    .to_string(),
                "20591505972264877134692628974262858389791935360235095823326480317993266462192"
                    .to_string(),
            ],
            pi_b: vec![
                vec![
                    "619236295498711744772585585128891674745469927597352249297212542897714664232"
                        .to_string(),
                    "1809058766164187894185026087275630817143803388124565244313926856319547861622"
                        .to_string(),
                ],
                vec![
                    "16801877216483442017291779563955902020454517191452306812496410647866027456043"
                        .to_string(),
                    "19259947654444516016740861069952616950514959798267205809958265209204287327638"
                        .to_string(),
                ],
            ],
            pi_c: vec![
                "6181620472369940654638786693008920183259441714605808170713998264123706831482"
                    .to_string(),
                "8476611896268564037882823317556955261481424484393929573128728099358097753265"
                    .to_string(),
            ],
        };
        let proof = circom_proof.to_proof();
        let key: Vec<u64> = vec![5, 6, 7, 8, 9];
        let value: Vec<String> = vec![
            "6603711446460119554941944208156960881066500660966266214060474870106078020334"
                .to_string(),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
                .to_string(),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
                .to_string(),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
                .to_string(),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
                .to_string(),
        ];
        let old_root: String =
            "1658838768171573723329052569061437764260952576948056211579533240085168463920"
                .to_string();
        let new_root: String =
            "478655864244704316729327101338170159019788786303319120441965758215699838829"
                .to_string();
        let public_signals: PublicSignals =
            PublicSignals::from_values(key, value, old_root, new_root);

        let verifier = Verifier::new(
            r#"{
                "vk_alpha_1": [
                 "2792344384149591757856311850681873062846176082098105379474477423151376877690",
                 "6236854853231948610200150794778218399683511893884507761111177575939538931174",
                 "1"
                ],
                "vk_beta_2": [
                 [
                  "3472935417295100727481483400528042372979093191121025934623444689528138019117",
                  "8486363979857715212974507855413309417946053107757071245251988207497455750751"
                 ],
                 [
                  "13971089571683312703817865921540000762505067051577915527389872831112401738671",
                  "529227951734104729755518261613769911348791304464556484589013210666061410692"
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
                "vk_alphabeta_12": [
                 [
                  [
                   "8039594245139529352945698399384827024419844572309028000410269394344045352080",
                   "2057072322385231075230395313193756509914722890835605772969817753461669361662"
                  ],
                  [
                   "1039639499678504747704931574244153239645704750754113015811166484676847658083",
                   "9939820945929699593998398038830828580972382933643216190522405904194172016641"
                  ],
                  [
                   "8926450038722399206033151708486231197163715984072097882069545013502378860998",
                   "7254845195735117149242676724586041774310549279578716629043578017332944953770"
                  ]
                 ],
                 [
                  [
                   "1034786205841626096479722071999449753321046523213965175461699878288893589328",
                   "5621811791121580284397873457820150356280151311255276318883387159141291662523"
                  ],
                  [
                   "4832504895711281439931947049119820599246056043986791262597746404889138425332",
                   "10308833052339899528611167226498783784279860509843864520430632066413786921554"
                  ],
                  [
                   "3827667142512945517420790565221657796517927659304877232966967641722636710099",
                   "1581256089394714810097177789560792351637980503977197885040174857327169909067"
                  ]
                 ]
                ],
                "IC": [
                 [
                  "17925460323737015296000517009957851964270786357732596480289818635801712726808",
                  "18684957821819605906701414748931470153973096761978127009331868463499122524052",
                  "1"
                 ],
                 [
                  "14067873537608590251725462753810209635269282737716351677798919798946962239451",
                  "2190139944768049510103837974769007051151627331517976355810535449729608964546",
                  "1"
                 ],
                 [
                  "18492540951579881361120571673751949194941767119176402266943650513777041323553",
                  "5920322977161707876924243336176157792142859239822518283949748769329197908794",
                  "1"
                 ],
                 [
                  "17770413600436677678478487396281201667330746537979545763618982315487297706469",
                  "590655158179939559677654792453947246984201904324824582970344394121537669477",
                  "1"
                 ],
                 [
                  "4438396101332558141253249963604640031283460531165045108524453559786067290539",
                  "16580142409000159087121386460006043141506613980382648972343909921753543637071",
                  "1"
                 ],
                 [
                  "851208411307781666430103780673037854787498008951249630081724846585357164336",
                  "5836196898067851117808517046875273402528729567155620742118568588738832086981",
                  "1"
                 ],
                 [
                  "17629996931410550618547477798886724246566252251604941152858494835880185244508",
                  "9370178660046202858360193468330475940022535270225062356707759495114421319576",
                  "1"
                 ],
                 [
                  "19784793511913841022936287989460594213472167912925423002568686922828692446666",
                  "18506706578855939916853634234616049018109127147527190186597343984904530236360",
                  "1"
                 ],
                 [
                  "18382971539923582892850105115078710830999356721008221266598401778684613177209",
                  "21209159649842354173419134052483983159863803590079055552977398029935796139245",
                  "1"
                 ],
                 [
                  "10623934269603338141477299566477266660813999279774149464880171287383897470749",
                  "10124357232613299341710383652949145004259232506539994735183040485881104620699",
                  "1"
                 ],
                 [
                  "1501081153303099314182660381676052777131686288347824318407451611166201957424",
                  "15088645019054311566114381288046810826553698097683347464989122967300843414915",
                  "1"
                 ],
                 [
                  "14015861967522284162286275939499181603633526834139033266098662867867069571663",
                  "18085439200878129601518284876685163461832901484441129289187381185681855990059",
                  "1"
                 ],
                 [
                  "15232900954500147460731546959275620279352996054994895573577836944403061957614",
                  "21685718989529363287585550543581274828011636099286856228096488025639545000307",
                  "1"
                 ]
                ]
               }"#
            .to_string(),
        );

        if !verifier.verify_proof(proof, &public_signals.get()) {
            println!("false");
        } else {
            println!("ok");
        }
    }
}
