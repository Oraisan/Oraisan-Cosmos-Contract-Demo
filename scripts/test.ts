//@ts-nocheck
import { SigningCosmWasmClient, Secp256k1HdWallet, setupWebKeplr, coin, UploadResult, InstantiateResult, toBinary } from "cosmwasm";
import { CosmWasmClient } from "cosmwasm";
import * as dotenv from "dotenv";
import { Decimal } from "@cosmjs/math";
import axios from 'axios';
import * as fs from "fs";
// import MerkleTree from "fixed-merkle-tree";
// import { buildMimc7 } from "circomlibjs";

dotenv.config();
// This is your rpc endpoint
const getTxAPI = "https://testnet-lcd.orai.io/cosmos/"

const rpcEndpoint = "https://testnet-rpc.orai.io:443/";
const chainID = "Oraichain-testnet"
const mnemonic = process.env.MNEMONIC!;

let mimc;
let F;
let tree;

function writeToEnvFile(key: String, value: String) {
    const envFilePath = '.env';
    const envString = `${key}=${value}`;

    try {
        if (fs.existsSync(envFilePath)) {
            let data = fs.readFileSync(envFilePath, 'utf8');
            const lines = data.trim().split('\n');
            let keyExists = false;
            const updatedLines = lines.map(line => {
                const [existingKey] = line.split('=');
                if (existingKey === key) {
                    keyExists = true;
                    return envString;
                }
                return line;
            });
            if (!keyExists) {
                updatedLines.push(envString);
            }
            const updatedData = updatedLines.join('\n');
            fs.writeFileSync(envFilePath, updatedData + '\n');
        } else {
            fs.writeFileSync(envFilePath, envString + '\n');
        }
        console.log('Successfully wrote to .env file.');
    } catch (err) {
        console.error('Error writing to .env file:', err);
    }
}

function saveUpdateDepositTreeTxToJsonFile(path: string, data: any) {
    // let txMessages: any[] = [];
    // for (let i = 0; i < data.body.messages.length; i++) {
    //     let txMessage = {
    //         "@type": data.body.messages[i]["@type"],
    //         sender: data.body.messages[i].sender,
    //         contract: data.body.messages[i].contract,
    //         msg: data.body.messages[i].msg
    //     }
    //     txMessages.push(txMessage)
    // }

    // let signer_infos: any[] = [];
    // for(let i = 0; i < data.auth_info.signer_infos.length; i++) {
    //     let signer_info = {
    //         public_key: {
    //             "@type": data.auth_info.signer_infos[i].public_key["@type"],
    //             key: data.auth_info.signer_infos[i].public_key.key
    //         },
    //         mode_info: {
    //             single: {
    //                 mode: data.auth_info.signer_infos[i].mode_info.single.mode
    //             }
    //         },
    //         sequence: data.auth_info.signer_infos[i].sequence
    //     }
    //     signer_infos.push(signer_info)
    // }

    // let amount: any[] = [];
    // for(let i = 0; i  < data.auth_info.fee.amount.length; i++) {
    //     let a = {
    //         denom: data.auth_info.fee.amount[i].denom,
    //         amount: data.auth_info.fee.amount[i].amount
    //     }
    //     amount.push(a);
    // }

    // let signatures: any[] = [];
    // for(let i = 0; i < data.signatures.length; i++){
    //     let signature = data.signatures[i];
    //     signatures.push(signature)
    // }

    // let txData = {
    //     body: {
    //         messages: txMessages,
    //         memo: data.body.memo,
    //         timeout_height: data.body.timeout_height,
    //         extension_options: data.body.extension_options,
    //         non_critical_extension_options: data.body.non_critical_extension_options
    //     },
    //     auth_info: {
    //         signer_infos: signer_infos,
    //         fee: {
    //             amount: amount,
    //             gas_limit: data.auth_info.fee.gas_limit,
    //             payer: data.auth_info.fee.payer,
    //             granter: data.auth_info.fee.granter
    //         }
    //     },
    //     signatures: signatures
    // }
    const jsonData = JSON.stringify(data, null, 2);
    fs.writeFileSync(path, jsonData, 'utf-8');
    console.log('Data has been saved to file:', path);
}

function ReadFile(path: string): Uint8Array {
    var file = fs.readFileSync(path);
    var buffer = new Uint8Array(file);
    return buffer
}

function ReadJsonFile(path: string): Record<string, any> {

    const jsonData = fs.readFileSync(path, 'utf-8');
    const parsedData: Record<string, any> = JSON.parse(jsonData);
    return parsedData;
}

function getInputUpdateDepositTree() {
    let proofFile: Record<string, any> = ReadJsonFile("./scripts/proofDepositTree/proof.json");
    let publicFile: Record<string, any> = ReadJsonFile("./scripts/proofDepositTree/public.json");
    let proof: any[] = [];
    for (let i = 0; i < 2; i++) {
        proof.push(proofFile.pi_a[i]);
    }
    for (let i = 0; i < 2; i++) {
        for (let j = 1; j >= 0; j--) {
            proof.push(proofFile.pi_b[i][j]);
        }
    }
    for (let i = 0; i < 2; i++) {
        proof.push(proofFile.pi_c[i]);
    }

    let msg = {
        update_deposit_tree: {
            root: publicFile[publicFile.length - 1],
            proof: proof,
        }
    }
    return msg
}

async function getWallet(): Promise<Secp256k1HdWallet> {
    const wallet = await Secp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "orai" });
    return wallet;
}
async function getClient(): Promise<SigningCosmWasmClient> {
    // Create a wallet
    const wallet = await getWallet();

    // Using
    const client = await SigningCosmWasmClient.connectWithSigner(
        rpcEndpoint,
        wallet,
        {
            gasPrice: {
                denom: "orai",
                amount: Decimal.fromUserInput("0.001", 6)
            }
        }
    );

    return client;
}

async function Upload(path): Promise<UploadResult> {
    // const query = await client.getTx("2D925C0F81EF1E26662B0A2A9277180CE853F9F07C60CA2F3E64E7F565A19F78")
    const wallet = await getWallet();
    const client = await getClient();

    const senderAddress = (await wallet.getAccounts())[0].address;
    const wasmCode = ReadFile(path)
    const fee = "auto"
    const memo: any = null
    // const fund = [coin(2, "orai")]
    // const res = await client.execute(senderAddress, contractAddress, msg, fee, memo, fund)
    const res = await client.upload(senderAddress, wasmCode, fee, memo)
    console.log(res)
    return res;
}

async function instantiate(codeID: number): Promise<InstantiateResult> {
    // const query = await client.getTx("2D925C0F81EF1E26662B0A2A9277180CE853F9F07C60CA2F3E64E7F565A19F78")
    const wallet = await getWallet();
    const client = await getClient();

    const senderAddress = (await wallet.getAccounts())[0].address;

    const msg = {
        token_address: process.env.COSMOS_TOKEN_ADDRESS,
        root: "19650381120764303012524736994073988891758455017340428694151271035030351959738"

    }
    const label = "Test ew20"

    const fee = "auto"
    // const option = {
    //     fund: {
    //         denom: "orai",
    //         amount: Decimal.fromUserInput("0.001", 6)
    //     },
    //     admin: senderAddress
    // }
    const res = await client.instantiate(senderAddress, codeID, msg, label, fee)
    console.log(res)
    return res;
}

async function sendToken(amount: String) {
    // const query = await client.getTx("2D925C0F81EF1E26662B0A2A9277180CE853F9F07C60CA2F3E64E7F565A19F78")
    const wallet = await getWallet();
    const client = await getClient();

    const senderAddress = (await wallet.getAccounts())[0].address;
    const contractAddress = process.env.COSMOS_TOKEN_ADDRESS || "";
    const msg_bridge = {
        eth_bridge_address: "0x66EeCaf1D881F7D828224422387b6fe0359AA69f",
        eth_receiver: "0x72e03B6E7AB9DdFe1699B65B8A46A3Cf30092020",
        value: "18712246956963994472991080367043956350605353057166171035306250565298571161961"
    }
    const msg = {
        send: {
            contract: process.env.COSMOS_BRIDGE_ADDRESS || "",
            amount: amount,
            msg: toBinary(msg_bridge)
        }
    }
    console.log("msg", msg);
    const fee = "auto"
    const memo: any = null
    const res = await client.execute(senderAddress, contractAddress, msg, fee, memo)
    console.log(res)
    return res;

}

async function updateDepositTree() {
    // const query = await client.getTx("2D925C0F81EF1E26662B0A2A9277180CE853F9F07C60CA2F3E64E7F565A19F78")
    const wallet = await getWallet();
    const client = await getClient();

    const senderAddress = (await wallet.getAccounts())[0].address;
    const contractAddress = process.env.COSMOS_BRIDGE_ADDRESS || "";
    const msg = getInputUpdateDepositTree();
    console.log("msg", msg);
    const fee = "auto"
    const memo: any = null
    const res = await client.execute(senderAddress, contractAddress, msg, fee, memo)
    console.log(res)
    return res;
}
// const initialize_deposit_tree = async () => {
//     mimc = await buildMimc7();
//     F = mimc.F;
//     tree = new MerkleTree(32);
// }

// const getTree = () => {
//     return tree;
// }



// function hash(arr: Array<any>) {
//     // return F.toObject(babyJub.unpackPoint(mimc.hash(L, R))[0]);
//     return F.toObject(mimc.multiHash(arr, 0));
// }

// const addLeaf = async (arr: Array<any>) => {
//     if (!tree) await initialize_deposit_tree();
//     const leaf = hash(arr);
//     tree.insert(leaf);
//     return tree._layers[0].length - 1;
// }

// const getSiblings = (index: number) => {
//     let { pathElements } = tree.path(index);
//     return pathElements;
// }

async function QueryDepositTree() {
    // const query = await client.getTx("2D925C0F81EF1E26662B0A2A9277180CE853F9F07C60CA2F3E64E7F565A19F78")
    const client = await getClient();

    const contract_address = process.env.COSMOS_BRIDGE_ADDRESS || "";
    const query_message = {
        deposit_tree: {}
    }
    const res = await client.queryContractSmart(contract_address, query_message)
    return res
}
async function QueryDepositQueue() {
    const client = await getClient();

    const contract_address = process.env.COSMOS_BRIDGE_ADDRESS || "";
    const query_message = {
        deposit_queue: {}
    }
    console.log("deposit_queue mssage", query_message);
    const res = await client.queryContractSmart(contract_address, query_message)
    return res
}

async function QueryTxByHash(txHash: string): Promise<any> {
    // console.log(resInitiate)
    // console.log(wasmCode)
    let res = await axios.get(getTxAPI + "tx/v1beta1/txs/" + txHash).then(function (response: any) {
        // handle success
        return {tx: response.data.tx, height: response.data.tx_response.height}
        // console.dir(response.data.tx, { depth: null });
    })
        .catch(function (error) {
            // handle error
            console.log(error);
        })
        .finally(function () {
            // always executed
        });

    return res
}

async function QueryBlockHeaderByHeight(height: string): Promise<any> {
    let res = await axios.get(getTxAPI + "tx/v1beta1/txs/block/" + height).then(function (response: any) {
        // handle success
        return {header: response.data.block.header, txs: response.data.block.data.txs}
        // console.dir(response.data.tx, { depth: null });
    })
        .catch(function (error) {
            // handle error
            console.log(error);
        })
        .finally(function () {
            // always executed
        });

    return res
}

async function main() {
    // const resUpload = await Upload("./artifacts/oraisan_cosmos_contract_demo.wasm");
    // const resInitiate = await instantiate(resUpload.codeId);
    // writeToEnvFile("COSMOS_BRIDGE_ADDRESS", resInitiate.contractAddress)
    // const resSendToken = await sendToken("10");
    // console.log("sendtoken", resSendToken)
    // const resDepositTree = await QueryDepositTree();
    // console.log("depositTree", resDepositTree);

    // const resDepositQueue = await QueryDepositQueue();
    // console.log(resDepositQueue);

    const resUpdate = await updateDepositTree();
    console.log(resUpdate);

    const resQueryDepositRootTx = await QueryTxByHash(resUpdate.transactionHash);
    console.log(resQueryDepositRootTx);
    saveUpdateDepositTreeTxToJsonFile("./scripts/proofDepositTree/tx_data.json", resQueryDepositRootTx.tx);
    const resQueryBlock = await QueryBlockHeaderByHeight(resQueryDepositRootTx.height);
    saveUpdateDepositTreeTxToJsonFile("./scripts/proofDepositTree/block.json", resQueryBlock);
    console.log(resQueryBlock)
}
main();