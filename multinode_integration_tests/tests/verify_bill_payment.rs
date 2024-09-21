// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use bip39::{Language, Mnemonic, Seed};
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::messages::FromMessageBody;
use masq_lib::messages::ToMessageBody;
use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
use masq_lib::percentage::PurePercentage;
use masq_lib::utils::{derivation_path, find_free_port, NeighborhoodModeLight};
use multinode_integration_tests_lib::blockchain::BlockchainServer;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, EarningWalletInfo, MASQRealNode, NodeNamingAndDir, NodeStartupConfig,
    NodeStartupConfigBuilder,
};
use multinode_integration_tests_lib::utils::UrlHolder;
use node_lib::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::accountant::gwei_to_wei;
use node_lib::blockchain::bip32::Bip32EncryptionKeyProvider;
use node_lib::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use node_lib::blockchain::blockchain_interface::BlockchainInterface;
use node_lib::database::db_initializer::{
    DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData,
};
use node_lib::sub_lib::accountant::PaymentThresholds;
use node_lib::sub_lib::blockchain_interface_web3::{
    compute_gas_limit, transaction_data_web3, web3_gas_limit_const_part,
};
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils;
use node_lib::test_utils::standard_dir_for_test_input_data;
use rustc_hex::{FromHex, ToHex};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{thread, u128};
use tiny_hderive::bip32::ExtendedPrivKey;
use web3::transports::Http;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, TransactionRequest};
use web3::Web3;

#[test]
fn full_payments_were_processed_for_sufficient_balances() {
    // Note: besides the main objectives of this test, it relies on (and so it proves) the premise
    // that each Node, after it achieves an effective connectivity as making a route is enabled,
    // activates the accountancy module whereas the first cycle of scanners is unleashed. That's
    // an excuse hopefully good enough not to take out the passage in this test with the intense
    // startup of a bunch of real Nodes, with the only purpose of fulfilling the conditions required
    // for going through that above depicted sequence of events. That said, this test could've been
    // written simpler with an emulated UI and its `scans` command, lowering the CPU burden.
    // (You may be pleased to know that such an approach is implemented for another test in this
    // file.)
    let payment_thresholds = PaymentThresholds {
        threshold_interval_sec: 2_500_000,
        debt_threshold_gwei: 1_000_000_000,
        payment_grace_period_sec: 85_000,
        maturity_threshold_sec: 85_000,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_below_gwei: 10_000_000,
    };
    let debt_threshold_wei = to_wei(payment_thresholds.debt_threshold_gwei);
    let owed_to_serving_node_1_minor = debt_threshold_wei + 123_456;
    let owed_to_serving_node_2_minor = debt_threshold_wei + 456_789;
    let owed_to_serving_node_3_minor = debt_threshold_wei + 789_012;
    let consuming_node_initial_service_fee_balance_minor = debt_threshold_wei * 4;
    let long_ago = UNIX_EPOCH.elapsed().unwrap().as_secs();
    let test_inputs = TestInputs {
        ui_ports_opt: None,
        consuming_node_initial_transaction_fee_balance_minor_opt: None,
        consuming_node_initial_service_fee_balance_minor,
        debts_config: DebtsSpecs {
            serving_node_1: Debt {
                balance_minor: owed_to_serving_node_1_minor,
                age_s: long_ago,
            },
            serving_node_2: Debt {
                balance_minor: owed_to_serving_node_2_minor,
                age_s: long_ago,
            },
            serving_node_3: Debt {
                balance_minor: owed_to_serving_node_3_minor,
                age_s: long_ago,
            },
        },
        payment_thresholds_all_nodes: payment_thresholds,
        consuming_node_gas_price_opt: None,
    };
    let final_consuming_node_service_fee_balance_minor =
        consuming_node_initial_service_fee_balance_minor
            - (owed_to_serving_node_1_minor
                + owed_to_serving_node_2_minor
                + owed_to_serving_node_3_minor);
    let assertions_values = AssertionsValues {
        final_consuming_node_transaction_fee_balance_minor: 999_842_470_000_000_000,
        final_consuming_node_service_fee_balance_minor,
        final_service_fee_balances: FinalServiceFeeBalancesByNode {
            node_1_minor: owed_to_serving_node_1_minor,
            node_2_minor: owed_to_serving_node_2_minor,
            node_3_minor: owed_to_serving_node_3_minor,
        },
    };

    test_body(
        test_inputs,
        assertions_values,
        stimulate_consuming_node_to_pay_for_test_with_sufficient_funds,
        activating_serving_nodes_for_test_with_sufficient_funds,
    );
}

fn stimulate_consuming_node_to_pay_for_test_with_sufficient_funds<'a>(
    cluster: &'a mut MASQNodeCluster,
    real_consuming_node: &'a MASQRealNode,
    _global_values: &'a GlobalValues,
) {
    for _ in 0..6 {
        cluster.start_real_node(
            NodeStartupConfigBuilder::standard()
                .chain(Chain::Dev)
                .neighbor(real_consuming_node.node_reference())
                .build(),
        );
    }
}

fn activating_serving_nodes_for_test_with_sufficient_funds<'a>(
    cluster: &'a mut MASQNodeCluster,
    serving_nodes: &'a mut [ServingNodeAttributes; 3],
    _global_values: &'a GlobalValues,
) -> [MASQRealNode; 3] {
    let (node_references, serving_nodes): (Vec<_>, Vec<_>) = serving_nodes
        .into_iter()
        .map(|attributes| {
            let namings = &attributes.common.namings;
            cluster.start_named_real_node(
                &namings.node_name,
                namings.index,
                attributes.common.config_opt.take().unwrap(),
            )
        })
        .map(|node| (node.node_reference(), node))
        .unzip();
    let auxiliary_node_config = node_references
        .into_iter()
        .fold(
            NodeStartupConfigBuilder::standard().chain(Chain::Dev),
            |builder, serving_node_reference| builder.neighbor(serving_node_reference),
        )
        .build();

    // Should be enough additional Nodes to provide the full connectivity
    for _ in 0..3 {
        let _ = cluster.start_real_node(auxiliary_node_config.clone());
    }

    serving_nodes.try_into().unwrap()
}

#[test]
fn payments_were_adjusted_due_to_insufficient_balances() {
    let payment_thresholds = PaymentThresholds {
        threshold_interval_sec: 2_500_000,
        debt_threshold_gwei: 100_000_000,
        payment_grace_period_sec: 85_000,
        maturity_threshold_sec: 85_000,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_below_gwei: 1_000_000,
    };
    // Assuming all Nodes rely on the same set of payment thresholds
    let owed_to_serv_node_1_minor = gwei_to_wei(payment_thresholds.debt_threshold_gwei + 5_000_000);
    let owed_to_serv_node_2_minor =
        gwei_to_wei(payment_thresholds.debt_threshold_gwei + 20_000_000);
    // Account of Node 3 will be a victim of tx fee insufficiency and will fall away, as its debt
    // is the heaviest, implying the smallest weight evaluated and the last priority compared to
    // those two others.
    let owed_to_serv_node_3_minor =
        gwei_to_wei(payment_thresholds.debt_threshold_gwei + 60_000_000);
    let enough_balance_for_serving_node_1_and_2 =
        owed_to_serv_node_1_minor + owed_to_serv_node_2_minor;
    let consuming_node_initial_service_fee_balance_minor =
        enough_balance_for_serving_node_1_and_2 - gwei_to_wei::<u128, _>(2_345_678_u64);
    let agreed_transaction_fee_unit_price_major = 60;
    let tx_fee_needed_to_pay_for_one_payment_major = {
        // We'll need littler funds, but we can stand mild inaccuracy from assuming the use of
        // all nonzero bytes in the data in both txs, which represents maximized costs
        let txn_data_with_maximized_costs = [0xff; 68];
        let gas_limit_dev_chain = {
            let const_part = web3_gas_limit_const_part(Chain::Dev);
            u64::try_from(compute_gas_limit(
                const_part,
                txn_data_with_maximized_costs.as_slice(),
            ))
            .unwrap()
        };
        let transaction_fee_margin = PurePercentage::try_from(15).unwrap();
        transaction_fee_margin
            .add_percent_to(gas_limit_dev_chain * agreed_transaction_fee_unit_price_major)
    };
    const AFFORDABLE_PAYMENTS_COUNT: u128 = 2;
    let tx_fee_needed_to_pay_for_one_payment_minor: u128 =
        gwei_to_wei(tx_fee_needed_to_pay_for_one_payment_major);
    let consuming_node_transaction_fee_balance_minor =
        AFFORDABLE_PAYMENTS_COUNT * tx_fee_needed_to_pay_for_one_payment_minor;
    let test_inputs = TestInputs {
        ui_ports_opt: Some(Ports {
            consuming_node: find_free_port(),
            serving_node_1: find_free_port(),
            serving_node_2: find_free_port(),
            serving_node_3: find_free_port(),
        }),
        // Should be enough only for two payments, the least significant one will fall out
        consuming_node_initial_transaction_fee_balance_minor_opt: Some(
            consuming_node_transaction_fee_balance_minor,
        ),
        consuming_node_initial_service_fee_balance_minor,
        debts_config: DebtsSpecs {
            // This account will be the most significant and will deserve the full balance
            serving_node_1: Debt {
                balance_minor: owed_to_serv_node_1_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 1000,
            },
            // This balance is of a middle size it will be reduced as there won't be enough
            // after the first one is filled up.
            serving_node_2: Debt {
                balance_minor: owed_to_serv_node_2_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 100_000,
            },
            // This account will be the least significant, therefore eliminated due to tx fee
            serving_node_3: Debt {
                balance_minor: owed_to_serv_node_3_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 30_000,
            },
        },
        payment_thresholds_all_nodes: payment_thresholds,
        consuming_node_gas_price_opt: Some(agreed_transaction_fee_unit_price_major),
    };

    let assertions_values = AssertionsValues {
        // How much is left after the smart contract was successfully executed, those three payments
        final_consuming_node_transaction_fee_balance_minor: 2_828_352_000_000_000,
        // Zero reached, because the algorithm is designed to exhaust the wallet completely
        final_consuming_node_service_fee_balance_minor: 0,
        // This account was granted with the full size as its lowest balance from the set makes
        // it weight the most
        final_service_fee_balances: FinalServiceFeeBalancesByNode {
            node_1_minor: owed_to_serv_node_1_minor,
            node_2_minor: owed_to_serv_node_2_minor - gwei_to_wei::<u128, u64>(2_345_678),
            // This account dropped out from the payment, so received no money
            node_3_minor: 0,
        },
    };

    test_body(
        test_inputs,
        assertions_values,
        stimulate_consuming_node_to_pay_for_test_with_insufficient_funds,
        activating_serving_nodes_for_test_with_insufficient_funds,
    );
}

fn stimulate_consuming_node_to_pay_for_test_with_insufficient_funds(
    _cluster: &mut MASQNodeCluster,
    real_consuming_node: &MASQRealNode,
    global_values: &GlobalValues,
) {
    process_scan_request_to_node(
        &real_consuming_node,
        global_values
            .test_inputs
            .port(NodeByRole::ConsumingNode)
            .unwrap(),
        ScanType::Payables,
        1111,
    )
}

fn activating_serving_nodes_for_test_with_insufficient_funds(
    cluster: &mut MASQNodeCluster,
    serving_nodes: &mut [ServingNodeAttributes; 3],
    global_values: &GlobalValues,
) -> [MASQRealNode; 3] {
    let real_nodes: Vec<_> = serving_nodes
        .iter_mut()
        .enumerate()
        .map(|(idx, serving_node_attributes)| {
            let node_config = serving_node_attributes.common.config_opt.take().unwrap();
            let common = &serving_node_attributes.common;
            let serving_node = cluster.start_named_real_node(
                &common.namings.node_name,
                common.namings.index,
                node_config,
            );
            let ui_port = global_values
                .test_inputs
                .port(common.node_by_role)
                .expect("ui port missing");

            process_scan_request_to_node(
                &serving_node,
                ui_port,
                ScanType::Receivables,
                (idx * 111) as u64,
            );

            serving_node
        })
        .collect();
    real_nodes.try_into().unwrap()
}

fn process_scan_request_to_node(
    real_node: &MASQRealNode,
    ui_port: u16,
    scan_type: ScanType,
    context_id: u64,
) {
    let ui_client = real_node.make_ui(ui_port);
    ui_client.send_request(UiScanRequest { scan_type }.tmb(context_id));
    let response = ui_client.wait_for_response(context_id, Duration::from_secs(10));
    UiScanResponse::fmb(response).expect("Scan request went wrong");
}

fn establish_test_frame(test_inputs: TestInputs) -> (MASQNodeCluster, GlobalValues) {
    let now = SystemTime::now();
    let cluster = match MASQNodeCluster::start() {
        Ok(cluster) => cluster,
        Err(e) => panic!("{}", e),
    };
    let blockchain_server = BlockchainServer {
        name: "ganache-cli",
    };
    blockchain_server.start();
    blockchain_server.wait_until_ready();
    let server_url = blockchain_server.url().to_string();
    let (event_loop_handle, http) =
        Http::with_max_parallel(&server_url, REQUESTS_IN_PARALLEL).unwrap();
    let web3 = Web3::new(http.clone());
    let seed = make_seed();
    let (contract_owner_wallet, _) = make_node_wallet(&seed, &derivation_path(0, 0));
    let contract_owner_addr = deploy_smart_contract(&contract_owner_wallet, &web3, cluster.chain);
    let blockchain_interface = Box::new(BlockchainInterfaceWeb3::new(
        http,
        event_loop_handle,
        cluster.chain,
    ));
    let blockchain_params = BlockchainParams {
        blockchain_interfaces: BlockchainInterfaces {
            blockchain_interface,
            web3,
        },
        chain: cluster.chain,
        server_url,
        contract_owner_addr,
        contract_owner_wallet,
        seed,
    };
    let global_values = GlobalValues {
        test_inputs,
        blockchain_params,
        now_in_common: now,
    };
    assert_eq!(
        contract_owner_addr,
        cluster.chain.rec().contract,
        "Either the contract has been modified or Ganache is not accurately mimicking Ethereum. \
         Resulted contact addr {:?} doesn't much what's expected: {:?}",
        contract_owner_addr,
        cluster.chain.rec().contract
    );

    (cluster, global_values)
}

fn to_wei(gwei: u64) -> u128 {
    gwei_to_wei(gwei)
}

fn make_db_init_config(chain: Chain) -> DbInitializationConfig {
    DbInitializationConfig::create_or_migrate(ExternalData::new(
        chain,
        NeighborhoodModeLight::Standard,
        None,
    ))
}

fn load_contract_in_bytes() -> Vec<u8> {
    let file_path =
        standard_dir_for_test_input_data().join("smart_contract_for_on_blockchain_test");
    let mut file = File::open(file_path).expect("couldn't acquire a handle to the data file");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    let data = data
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect::<String>();
    data.from_hex::<Vec<u8>>()
        .expect("bad contract: contains non-hexadecimal characters")
}

fn deploy_smart_contract(wallet: &Wallet, web3: &Web3<Http>, chain: Chain) -> Address {
    let contract = load_contract_in_bytes();
    let gas_price = to_wei(50);
    let gas_limit = 1_000_000_u64;
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::try_from(0).expect("Internal error")),
        to: None,
        gas: ethereum_types::U256::try_from(gas_limit).expect("Internal error"),
        gas_price: Some(ethereum_types::U256::try_from(gas_price).expect("Internal error")),
        value: ethereum_types::U256::zero(),
        data: Bytes(contract),
        chain_id: Some(chain.rec().num_chain_id),
    };
    let signed_tx = primitive_sign_transaction(web3, tx, wallet);
    match web3
        .eth()
        .send_raw_transaction(signed_tx.raw_transaction)
        .wait()
    {
        Ok(tx_hash) => match web3.eth().transaction_receipt(tx_hash).wait() {
            Ok(Some(tx_receipt)) => Address {
                0: tx_receipt.contract_address.unwrap().0,
            },
            Ok(None) => panic!("Contract deployment failed Ok(None)"),
            Err(e) => panic!("Contract deployment failed {:?}", e),
        },
        Err(e) => panic!("Contract deployment failed {:?}", e),
    }
}

fn transfer_service_fee_amount_to_address(
    contract_addr: Address,
    from_wallet: &Wallet,
    to_wallet: &Wallet,
    amount_minor: u128,
    transaction_nonce: u64,
    web3: &Web3<Http>,
    chain: Chain,
) {
    let data = transaction_data_web3(to_wallet, amount_minor);
    let gas_price_wei = to_wei(150);
    let gas_limit = 1_000_000_u64;
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::try_from(transaction_nonce).expect("Internal error")),
        to: Some(contract_addr),
        gas: ethereum_types::U256::try_from(gas_limit).expect("Internal error"),
        gas_price: Some(ethereum_types::U256::try_from(gas_price_wei).expect("Internal error")),
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };
    let signed_tx = primitive_sign_transaction(web3, tx, from_wallet);
    match web3
        .eth()
        .send_raw_transaction(signed_tx.raw_transaction)
        .wait()
    {
        Ok(tx_hash) => eprintln!(
            "Transaction {:?} of {} wei of MASQ was sent from wallet {} to {}",
            tx_hash, amount_minor, from_wallet, to_wallet
        ),
        Err(e) => panic!("Transaction for token transfer failed {:?}", e),
    }
}

fn primitive_sign_transaction(
    web3: &Web3<Http>,
    tx: TransactionParameters,
    signing_wallet: &Wallet,
) -> SignedTransaction {
    web3.accounts()
        .sign_transaction(
            tx,
            &signing_wallet
                .prepare_secp256k1_secret()
                .expect("wallet without secret"),
        )
        .wait()
        .expect("transaction preparation failed")
}

fn transfer_transaction_fee_amount_to_address(
    from_wallet: &Wallet,
    to_wallet: &Wallet,
    amount_minor: u128,
    transaction_nonce: u64,
    web3: &Web3<Http>,
) {
    let gas_price_wei = to_wei(150);
    let gas_limit = 1_000_000_u64;
    let tx = TransactionRequest {
        from: from_wallet.address(),
        to: Some(to_wallet.address()),
        gas: Some(ethereum_types::U256::try_from(gas_limit).expect("Internal error")),
        gas_price: Some(ethereum_types::U256::try_from(gas_price_wei).expect("Internal error")),
        value: Some(ethereum_types::U256::from(amount_minor)),
        data: None,
        nonce: Some(ethereum_types::U256::try_from(transaction_nonce).expect("Internal error")),
        condition: None,
    };
    match web3
        .personal()
        .unlock_account(from_wallet.address(), "", None)
        .wait()
    {
        Ok(was_successful) => {
            if was_successful {
                eprintln!("Account {} unlocked for a single transaction", from_wallet)
            } else {
                panic!(
                    "Couldn't unlock account {} for the purpose of signing the next transaction",
                    from_wallet
                )
            }
        }
        Err(e) => panic!(
            "Attempt to unlock account {:?} failed at {:?}",
            from_wallet.address(),
            e
        ),
    }
    match web3.eth().send_transaction(tx).wait() {
        Ok(tx_hash) => eprintln!(
            "Transaction {:?} of {} wei of ETH was sent from wallet {:?} to {:?}",
            tx_hash, amount_minor, from_wallet, to_wallet
        ),
        Err(e) => panic!("Transaction for token transfer failed {:?}", e),
    }
}

fn assert_balances(
    wallet: &Wallet,
    blockchain_interface: &dyn BlockchainInterface,
    expected_eth_balance: u128,
    expected_token_balance: u128,
) {
    let eth_balance = blockchain_interface
        .lower_interface()
        .get_transaction_fee_balance(&wallet)
        .unwrap_or_else(|_| panic!("Failed to retrieve gas balance for {}", wallet));
    assert_eq!(
        eth_balance,
        web3::types::U256::from(expected_eth_balance),
        "Actual EthBalance {} doesn't much with expected {} for {}",
        eth_balance,
        expected_eth_balance,
        wallet
    );
    let token_balance = blockchain_interface
        .lower_interface()
        .get_service_fee_balance(&wallet)
        .unwrap_or_else(|_| panic!("Failed to retrieve masq balance for {}", wallet));
    assert_eq!(
        token_balance,
        web3::types::U256::from(expected_token_balance),
        "Actual TokenBalance {} doesn't match with expected {} for {}",
        token_balance,
        expected_token_balance,
        wallet
    );
}

fn make_node_wallet(seed: &Seed, derivation_path: &str) -> (Wallet, String) {
    let extended_priv_key = ExtendedPrivKey::derive(&seed.as_ref(), derivation_path).unwrap();
    let secret = extended_priv_key.secret().to_hex::<String>();

    (
        Wallet::from(Bip32EncryptionKeyProvider::from_key(extended_priv_key)),
        secret,
    )
}

const MNEMONIC_PHRASE: &str =
    "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle \
    lamp absent write kind term toddler sphere ripple idle dragon curious hold";

fn make_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(MNEMONIC_PHRASE, Language::English).unwrap();
    Seed::new(&mnemonic, "")
}

struct TestInputs {
    ui_ports_opt: Option<Ports>,
    // The contract owner wallet is populated with 100 ETH as defined in the set of commands
    // with which we start up the Ganache server.
    //
    // Specify number of wei this account should possess at its initialisation.
    // The consuming node gets the full balance of the contract owner if left as None.
    // Cannot ever get more than what the "owner" has.
    consuming_node_initial_transaction_fee_balance_minor_opt: Option<u128>,
    consuming_node_initial_service_fee_balance_minor: u128,
    debts_config: DebtsSpecs,
    payment_thresholds_all_nodes: PaymentThresholds,
    consuming_node_gas_price_opt: Option<u64>,
}

struct AssertionsValues {
    final_consuming_node_transaction_fee_balance_minor: u128,
    final_consuming_node_service_fee_balance_minor: u128,
    final_service_fee_balances: FinalServiceFeeBalancesByNode,
}

struct FinalServiceFeeBalancesByNode {
    node_1_minor: u128,
    node_2_minor: u128,
    node_3_minor: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeByRole {
    ConsumingNode = 1,
    ServingNode1 = 2,
    ServingNode2 = 3,
    ServingNode3 = 4,
}

struct BlockchainParams {
    blockchain_interfaces: BlockchainInterfaces,
    chain: Chain,
    server_url: String,
    contract_owner_addr: Address,
    contract_owner_wallet: Wallet,
    seed: Seed,
}

struct BlockchainInterfaces {
    blockchain_interface: Box<dyn BlockchainInterface>,
    web3: Web3<Http>,
}

struct GlobalValues {
    test_inputs: TestInputs,
    blockchain_params: BlockchainParams,
    now_in_common: SystemTime,
}

struct WholesomeConfig {
    global_values: GlobalValues,
    consuming_node: ConsumingNodeAttributes,
    serving_nodes: [ServingNodeAttributes; 3],
}

struct DebtsSpecs {
    serving_node_1: Debt,
    serving_node_2: Debt,
    serving_node_3: Debt,
}

#[derive(Copy, Clone)]
struct Debt {
    balance_minor: u128,
    age_s: u64,
}

impl Debt {
    fn proper_timestamp(&self, now: SystemTime) -> SystemTime {
        now.checked_sub(Duration::from_secs(self.age_s)).unwrap()
    }
}

impl TestInputs {
    fn port(&self, requested: NodeByRole) -> Option<u16> {
        self.ui_ports_opt.as_ref().map(|ports| match requested {
            NodeByRole::ConsumingNode => ports.consuming_node,
            NodeByRole::ServingNode1 => ports.serving_node_1,
            NodeByRole::ServingNode2 => ports.serving_node_2,
            NodeByRole::ServingNode3 => ports.serving_node_3,
        })
    }

    fn debt_specs(&self, requested: NodeByRole) -> Debt {
        match requested {
            NodeByRole::ServingNode1 => self.debts_config.serving_node_1,
            NodeByRole::ServingNode2 => self.debts_config.serving_node_2,
            NodeByRole::ServingNode3 => self.debts_config.serving_node_3,
            NodeByRole::ConsumingNode => panic!(
                "Version fully specified: These configs \
                describe debts owed to the consuming node, while that one should not \
                be here."
            ),
        }
    }
}

impl GlobalValues {
    fn get_node_config_and_wallet(&self, node_by_role: NodeByRole) -> (NodeStartupConfig, Wallet) {
        let wallet_derivation_path = node_by_role.derivation_path();
        let payment_thresholds = self.test_inputs.payment_thresholds_all_nodes;
        let (node_wallet, node_secret) = make_node_wallet(
            &self.blockchain_params.seed,
            wallet_derivation_path.as_str(),
        );
        let mut cfg_to_build = NodeStartupConfigBuilder::standard()
            .blockchain_service_url(&self.blockchain_params.server_url)
            .chain(Chain::Dev)
            .payment_thresholds(payment_thresholds)
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(node_secret))
            .earning_wallet_info(EarningWalletInfo::Address(format!(
                "{}",
                node_wallet.clone()
            )));
        if let Some(port) = self.test_inputs.port(node_by_role) {
            cfg_to_build = cfg_to_build.ui_port(port)
        }
        if let Some(price) = self.test_inputs.consuming_node_gas_price_opt {
            cfg_to_build = cfg_to_build.gas_price(price)
        }

        eprintln!("{:?} wallet established: {}\n", node_by_role, node_wallet,);

        (cfg_to_build.build(), node_wallet)
    }

    fn prepare_consuming_node(
        &self,
        cluster: &mut MASQNodeCluster,
        blockchain_interfaces: &BlockchainInterfaces,
    ) -> ConsumingNodeAttributes {
        let (consuming_node_config, consuming_node_wallet) =
            self.get_node_config_and_wallet(NodeByRole::ConsumingNode);
        let initial_transaction_fee_balance = self
            .test_inputs
            .consuming_node_initial_transaction_fee_balance_minor_opt
            .unwrap_or(ONE_ETH_IN_WEI);
        transfer_transaction_fee_amount_to_address(
            &self.blockchain_params.contract_owner_wallet,
            &consuming_node_wallet,
            initial_transaction_fee_balance,
            1,
            &blockchain_interfaces.web3,
        );
        transfer_service_fee_amount_to_address(
            self.blockchain_params.contract_owner_addr,
            &self.blockchain_params.contract_owner_wallet,
            &consuming_node_wallet,
            self.test_inputs
                .consuming_node_initial_service_fee_balance_minor,
            2,
            &blockchain_interfaces.web3,
            self.blockchain_params.chain,
        );
        assert_balances(
            &consuming_node_wallet,
            blockchain_interfaces.blockchain_interface.as_ref(),
            initial_transaction_fee_balance,
            self.test_inputs
                .consuming_node_initial_service_fee_balance_minor,
        );
        let consuming_node_namings = cluster.prepare_real_node(&consuming_node_config);
        let consuming_node_connection = DbInitializerReal::default()
            .initialize(
                Path::new(&consuming_node_namings.db_path),
                make_db_init_config(cluster.chain),
            )
            .unwrap();
        let consuming_node_payable_dao = PayableDaoReal::new(consuming_node_connection);
        ConsumingNodeAttributes::new(
            NodeByRole::ConsumingNode,
            consuming_node_namings,
            Some(consuming_node_config),
            consuming_node_wallet,
            consuming_node_payable_dao,
        )
    }

    fn prepare_serving_nodes(&self, cluster: &mut MASQNodeCluster) -> [ServingNodeAttributes; 3] {
        [
            NodeByRole::ServingNode1,
            NodeByRole::ServingNode2,
            NodeByRole::ServingNode3,
        ]
        .into_iter()
        .map(|node_by_role: NodeByRole| {
            let (serving_node_config, serving_node_earning_wallet) =
                self.get_node_config_and_wallet(node_by_role);
            let serving_node_namings = cluster.prepare_real_node(&serving_node_config);
            let serving_node_connection = DbInitializerReal::default()
                .initialize(
                    &serving_node_namings.db_path,
                    make_db_init_config(cluster.chain),
                )
                .unwrap();
            let serving_node_receivable_dao = ReceivableDaoReal::new(serving_node_connection);
            ServingNodeAttributes::new(
                node_by_role,
                serving_node_namings,
                Some(serving_node_config),
                serving_node_earning_wallet,
                serving_node_receivable_dao,
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("failed to make [T;3] of provided Vec<T>")
    }

    fn set_start_block_to_zero(path: &Path) {
        DbInitializerReal::default()
            .initialize(path, DbInitializationConfig::panic_on_migration())
            .unwrap()
            .prepare("update config set value = '0' where name = 'start_block'")
            .unwrap()
            .execute([])
            .unwrap();
    }

    fn serving_node_debt_balance_and_timestamp(
        &self,
        attributes: &ServingNodeAttributes,
    ) -> (u128, SystemTime) {
        let node_role = attributes.common.node_by_role;
        let debt_specs = self.test_inputs.debt_specs(node_role);
        (
            debt_specs.balance_minor,
            debt_specs.proper_timestamp(self.now_in_common),
        )
    }

    fn set_up_serving_nodes_databases(
        &self,
        serving_nodes_matrix: &[ServingNodeAttributes; 3],
        consuming_node_attributes: &ConsumingNodeAttributes,
    ) {
        serving_nodes_matrix.iter().for_each(|node_attributes| {
            let (balance, timestamp) =
                self.serving_node_debt_balance_and_timestamp(node_attributes);
            node_attributes
                .receivable_dao
                .more_money_receivable(
                    timestamp,
                    &consuming_node_attributes.consuming_wallet,
                    balance,
                )
                .unwrap();
            assert_balances(
                &node_attributes.earning_wallet,
                self.blockchain_params
                    .blockchain_interfaces
                    .blockchain_interface
                    .as_ref(),
                0,
                0,
            );
            Self::set_start_block_to_zero(&node_attributes.common.namings.db_path)
        })
    }

    fn set_up_consuming_node_db(
        &self,
        serving_nodes_array: &[ServingNodeAttributes; 3],
        consuming_node_attributes: &ConsumingNodeAttributes,
    ) {
        serving_nodes_array.iter().for_each(|node_attributes| {
            let (balance, timestamp) =
                self.serving_node_debt_balance_and_timestamp(node_attributes);
            consuming_node_attributes
                .payable_dao
                .more_money_payable(timestamp, &node_attributes.earning_wallet, balance)
                .unwrap();
        });
        Self::set_start_block_to_zero(&consuming_node_attributes.common.namings.db_path)
    }
}

impl WholesomeConfig {
    fn new(
        global_values: GlobalValues,
        consuming_node: ConsumingNodeAttributes,
        serving_nodes: [ServingNodeAttributes; 3],
    ) -> Self {
        WholesomeConfig {
            global_values,
            consuming_node,
            serving_nodes,
        }
    }

    fn assert_expected_wallet_addresses(&self) {
        let consuming_node_actual = self.consuming_node.consuming_wallet.to_string();
        let consuming_node_expected = "0x7a3cf474962646b18666b5a5be597bb0af013d81";
        assert_eq!(
            &consuming_node_actual, consuming_node_expected,
            "Consuming Node's wallet {} mismatched with expected {}",
            consuming_node_actual, consuming_node_expected
        );
        vec![
            "0x0bd8bc4b8aba5d8abf13ea78a6668ad0e9985ad6",
            "0xb329c8b029a2d3d217e71bc4d188e8e1a4a8b924",
            "0xb45a33ef3e3097f34c826369b74141ed268cdb5a",
        ]
        .iter()
        .zip(self.serving_nodes.iter())
        .for_each(|(expected_wallet_addr, serving_node_attributes)| {
            let serving_node_actual = serving_node_attributes.earning_wallet.to_string();
            assert_eq!(
                &serving_node_actual,
                expected_wallet_addr,
                "{:?} wallet {} mismatched with expected {}",
                serving_node_attributes.common.node_by_role,
                serving_node_actual,
                expected_wallet_addr
            );
        })
    }

    fn assert_payments_via_direct_blockchain_scanning(&self, assertions_values: &AssertionsValues) {
        let blockchain_interface = self
            .global_values
            .blockchain_params
            .blockchain_interfaces
            .blockchain_interface
            .as_ref();
        assert_balances(
            &self.consuming_node.consuming_wallet,
            blockchain_interface,
            assertions_values.final_consuming_node_transaction_fee_balance_minor,
            assertions_values.final_consuming_node_service_fee_balance_minor,
        );
        assertions_values
            .serving_nodes_actually_received_payments()
            .into_iter()
            .zip(self.serving_nodes.iter())
            .for_each(|(expected_remaining_owed_value, serving_node)| {
                assert_balances(
                    &serving_node.earning_wallet,
                    blockchain_interface,
                    0,
                    expected_remaining_owed_value,
                );
            })
    }

    fn assert_serving_nodes_addressed_received_payments(
        &self,
        assertions_values: &AssertionsValues,
    ) {
        let actually_received_payments = assertions_values.serving_nodes_actually_received_payments();
        let consuming_node_wallet = &self.consuming_node.consuming_wallet;
        self.serving_nodes
            .iter()
            .zip(actually_received_payments.into_iter())
            .for_each(|(serving_node, received_payment)| {
                let original_debt = self.global_values
                    .test_inputs
                    .debt_specs(serving_node.common.node_by_role)
                    .balance_minor;
                let expected_final_balance = original_debt - received_payment;
                Self::wait_for_exact_balance_in_receivables(
                    &serving_node.receivable_dao,
                    expected_final_balance,
                    consuming_node_wallet,
                )
            })
    }

    fn wait_for_exact_balance_in_receivables(
        node_receivable_dao: &ReceivableDaoReal,
        expected_value: u128,
        consuming_node_wallet: &Wallet,
    ) {
        test_utils::wait_for(Some(1000), Some(15000), || {
            if let Some(status) = node_receivable_dao.account_status(&consuming_node_wallet) {
                status.balance_wei == i128::try_from(expected_value).unwrap()
            } else {
                false
            }
        });
    }
}

impl AssertionsValues {
    fn serving_nodes_actually_received_payments(&self) -> [u128; 3] {
        [
            self.final_service_fee_balances.node_1_minor,
            self.final_service_fee_balances.node_2_minor,
            self.final_service_fee_balances.node_3_minor,
        ]
    }
}

impl NodeByRole {
    fn derivation_path(self) -> String {
        derivation_path(0, self as usize as u8)
    }
}

const ONE_ETH_IN_WEI: u128 = 1_000_000_000_000_000_000;

struct Ports {
    consuming_node: u16,
    serving_node_1: u16,
    serving_node_2: u16,
    serving_node_3: u16,
}

#[derive(Debug)]
struct NodeAttributesCommon {
    node_by_role: NodeByRole,
    namings: NodeNamingAndDir,
    config_opt: Option<NodeStartupConfig>,
}

#[derive(Debug)]
struct ConsumingNodeAttributes {
    common: NodeAttributesCommon,
    consuming_wallet: Wallet,
    payable_dao: PayableDaoReal,
}

#[derive(Debug)]
struct ServingNodeAttributes {
    common: NodeAttributesCommon,
    earning_wallet: Wallet,
    receivable_dao: ReceivableDaoReal,
}

impl ConsumingNodeAttributes {
    fn new(
        node_by_role: NodeByRole,
        namings: NodeNamingAndDir,
        config_opt: Option<NodeStartupConfig>,
        consuming_wallet: Wallet,
        payable_dao: PayableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon {
            node_by_role,
            namings,
            config_opt,
        };
        Self {
            common,
            consuming_wallet,
            payable_dao,
        }
    }
}

impl ServingNodeAttributes {
    fn new(
        node_by_role: NodeByRole,
        namings: NodeNamingAndDir,
        config_opt: Option<NodeStartupConfig>,
        earning_wallet: Wallet,
        receivable_dao: ReceivableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon {
            node_by_role,
            namings,
            config_opt,
        };
        Self {
            common,
            earning_wallet,
            receivable_dao,
        }
    }
}

type StimulateConsumingNodePayments =
    for<'a> fn(&'a mut MASQNodeCluster, &'a MASQRealNode, &'a GlobalValues);

type StartServingNodesAndLetThemPerformReceivablesCheck = for<'a> fn(
    &'a mut MASQNodeCluster,
    &'a mut [ServingNodeAttributes; 3],
    &'a GlobalValues,
) -> [MASQRealNode; 3];

fn test_body(
    test_inputs: TestInputs,
    assertions_values: AssertionsValues,
    stimulate_consuming_node_to_pay: StimulateConsumingNodePayments,
    start_serving_nodes_and_activate_their_accountancy: StartServingNodesAndLetThemPerformReceivablesCheck,
) {
    let (mut cluster, global_values) = establish_test_frame(test_inputs);
    let consuming_node_attributes = global_values.prepare_consuming_node(
        &mut cluster,
        &global_values.blockchain_params.blockchain_interfaces,
    );
    let serving_nodes_array = global_values.prepare_serving_nodes(&mut cluster);
    global_values.set_up_consuming_node_db(&serving_nodes_array, &consuming_node_attributes);
    global_values.set_up_serving_nodes_databases(&serving_nodes_array, &consuming_node_attributes);
    let mut wholesome_config = WholesomeConfig::new(
        global_values,
        consuming_node_attributes,
        serving_nodes_array,
    );
    wholesome_config.assert_expected_wallet_addresses();
    let real_consuming_node = cluster.start_named_real_node(
        &wholesome_config.consuming_node.common.namings.node_name,
        wholesome_config.consuming_node.common.namings.index,
        wholesome_config
            .consuming_node
            .common
            .config_opt
            .take()
            .unwrap(),
    );

    stimulate_consuming_node_to_pay(
        &mut cluster,
        &real_consuming_node,
        &wholesome_config.global_values,
    );

    let timeout_start = Instant::now();
    while !wholesome_config
        .consuming_node
        .payable_dao
        .non_pending_payables()
        .is_empty()
        && timeout_start.elapsed() < Duration::from_secs(10)
    {
        thread::sleep(Duration::from_millis(400));
    }
    wholesome_config.assert_payments_via_direct_blockchain_scanning(&assertions_values);

    let _ = start_serving_nodes_and_activate_their_accountancy(
        &mut cluster,
        // So that individual Configs can be pulled out and used
        &mut wholesome_config.serving_nodes,
        &wholesome_config.global_values,
    );

    wholesome_config.assert_serving_nodes_addressed_received_payments(&assertions_values)
}
