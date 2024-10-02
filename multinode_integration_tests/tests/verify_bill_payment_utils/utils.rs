// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use bip39::{Language, Mnemonic, Seed};
use futures::Future;
use lazy_static::lazy_static;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::{derivation_path, NeighborhoodModeLight};
use multinode_integration_tests_lib::blockchain::BlockchainServer;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, EarningWalletInfo, MASQRealNode, NodeStartupConfig,
    NodeStartupConfigBuilder, PreparedNodeInfo,
};
use multinode_integration_tests_lib::utils::{open_all_file_permissions, UrlHolder};
use node_lib::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::accountant::gwei_to_wei;
use node_lib::blockchain::bip32::Bip32EncryptionKeyProvider;
use node_lib::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
};
use node_lib::blockchain::blockchain_interface::lower_level_interface::{
    LowBlockchainInt, ResultForBalance,
};
use node_lib::blockchain::blockchain_interface::BlockchainInterface;
use node_lib::database::db_initializer::{
    DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData,
};
use node_lib::sub_lib::accountant::PaymentThresholds;
use node_lib::sub_lib::blockchain_interface_web3::transaction_data_web3;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils;
use node_lib::test_utils::standard_dir_for_test_input_data;
use rustc_hex::{FromHex, ToHex};
use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use itertools::Itertools;
use tiny_hderive::bip32::ExtendedPrivKey;
use web3::transports::Http;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, TransactionRequest};
use web3::Web3;

pub type StimulateConsumingNodePayments = fn(&mut MASQNodeCluster, &MASQRealNode, &WholesomeConfig);

pub type StartServingNodesAndLetThemPerformReceivablesCheck =
    fn(&mut MASQNodeCluster, &WholesomeConfig) -> [MASQRealNode; 3];

pub fn test_body(
    test_inputs: TestInputs,
    assertions_values: AssertionsValues,
    stimulate_consuming_node_to_pay: StimulateConsumingNodePayments,
    start_serving_nodes_and_activate_their_accountancy: StartServingNodesAndLetThemPerformReceivablesCheck,
) {
    // It's important to prevent the blockchain server handle being dropped too early
    let (mut cluster, global_values, _blockchain_server) = establish_test_frame(test_inputs);
    let consuming_node =
        global_values.prepare_consuming_node(&mut cluster, &global_values.blockchain_interfaces);
    let serving_nodes_array = global_values.prepare_serving_nodes(&mut cluster);
    global_values.set_up_consuming_node_db(&serving_nodes_array, &consuming_node);
    global_values.set_up_serving_nodes_databases(&serving_nodes_array, &consuming_node);
    let wholesome_config = WholesomeConfig::new(global_values, consuming_node, serving_nodes_array);
    wholesome_config.assert_expected_wallet_addresses();
    let real_consuming_node = cluster.start_named_real_node(
        &wholesome_config
            .consuming_node
            .common
            .prepared_node
            .node_docker_name,
        wholesome_config.consuming_node.common.prepared_node.index,
        wholesome_config
            .consuming_node
            .common
            .startup_config_opt
            .borrow_mut()
            .take()
            .unwrap(),
    );

    stimulate_consuming_node_to_pay(&mut cluster, &real_consuming_node, &wholesome_config);

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
        &wholesome_config,
    );

    wholesome_config.assert_serving_nodes_addressed_received_payments(&assertions_values)
}

const MNEMONIC_PHRASE: &str =
    "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle \
    lamp absent write kind term toddler sphere ripple idle dragon curious hold";

pub struct TestInputs {
    // The contract owner wallet is populated with 100 ETH as defined in the set of commands with
    // which we start up the Ganache server.
    //
    // This specifies number of wei this account should possess at its initialisation.
    // The consuming node gets the full balance of the contract owner if left as None. Cannot ever
    // get more than what the "owner" has.
    payment_thresholds_all_nodes: PaymentThresholds,
    node_profiles: NodeProfiles,
}

#[derive(Default)]
pub struct TestInputsBuilder {
    ui_ports_opt: Option<Ports>,
    consuming_node_initial_tx_fee_balance_minor_opt: Option<u128>,
    consuming_node_initial_service_fee_balance_minor_opt: Option<u128>,
    debts_config_opt: Option<DebtsSpecs>,
    payment_thresholds_all_nodes_opt: Option<PaymentThresholds>,
    consuming_node_gas_price_opt: Option<u64>,
}

impl TestInputsBuilder {
    pub fn ui_ports(mut self, ports: Ports) -> Self {
        self.ui_ports_opt = Some(ports);
        self
    }

    pub fn consuming_node_initial_tx_fee_balance_minor(mut self, balance: u128) -> Self {
        self.consuming_node_initial_tx_fee_balance_minor_opt = Some(balance);
        self
    }

    pub fn consuming_node_initial_service_fee_balance_minor(mut self, balance: u128) -> Self {
        self.consuming_node_initial_service_fee_balance_minor_opt = Some(balance);
        self
    }

    pub fn debts_config(mut self, debts: DebtsSpecs) -> Self {
        self.debts_config_opt = Some(debts);
        self
    }

    pub fn payment_thresholds_all_nodes(mut self, thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds_all_nodes_opt = Some(thresholds);
        self
    }

    pub fn consuming_node_gas_price_major(mut self, gas_price: u64) -> Self {
        self.consuming_node_gas_price_opt = Some(gas_price);
        self
    }

    pub fn build(self) -> TestInputs {
        let mut debts = self
            .debts_config_opt
            .expect("You forgot providing a mandatory input: debts config")
            .debts
            .to_vec();
        let (consuming_node_ui_port_opt, serving_nodes_ui_ports_opt) = Self::resolve_ports(self.ui_ports_opt);
        let mut serving_nodes_ui_ports_opt = serving_nodes_ui_ports_opt.to_vec();
        let consuming_node = ConsumingNodeProfile {
            ui_port_opt: consuming_node_ui_port_opt,
            gas_price_opt: self.consuming_node_gas_price_opt,
            initial_tx_fee_balance_minor_opt: self.consuming_node_initial_tx_fee_balance_minor_opt,
            initial_service_fee_balance_minor: self
                .consuming_node_initial_service_fee_balance_minor_opt
                .expect("Mandatory input not provided: consuming node initial service fee balance"),
        };
        let mut serving_nodes = [
            ServingNodeByName::ServingNode1,
            ServingNodeByName::ServingNode2,
            ServingNodeByName::ServingNode3,
        ]
        .into_iter()
        .map(|serving_node_by_name|{
            let debt = debts.remove(0);
            let ui_port_opt = serving_nodes_ui_ports_opt.remove(0);
            ServingNodeProfile {
            serving_node_by_name,
            debt,
            ui_port_opt,
        }})
        .collect::<Vec<_>>();
        let node_profiles = NodeProfiles {
            consuming_node,
            serving_nodes: core::array::from_fn(|_| serving_nodes.remove(0)),
        };

        TestInputs {
            payment_thresholds_all_nodes: self
                .payment_thresholds_all_nodes_opt
                .expect("Mandatory input not provided: payment thresholds"),
            node_profiles,
        }
    }

    fn resolve_ports(ui_ports_opt: Option<Ports>) -> (Option<u16>, [Option<u16>; 3]) {
        match ui_ports_opt {
            Some(ui_ports) => {
                let mut ui_ports_as_opt = ui_ports.serving_nodes.into_iter().map(Some).collect_vec();
                let serving_nodes_array: [Option<u16>; 3] = core::array::from_fn(|_| ui_ports_as_opt.remove(0));
                (Some(ui_ports.consuming_node), serving_nodes_array)
            }
            None => Default::default(),
        }
    }
}

struct NodeProfiles {
    consuming_node: ConsumingNodeProfile,
    serving_nodes: [ServingNodeProfile; 3],
}

#[derive(Debug, Clone)]
pub struct ConsumingNodeProfile {
    ui_port_opt: Option<u16>,
    gas_price_opt: Option<u64>,
    initial_tx_fee_balance_minor_opt: Option<u128>,
    initial_service_fee_balance_minor: u128,
}

#[derive(Debug, Clone)]
pub struct ServingNodeProfile {
    serving_node_by_name: ServingNodeByName,
    debt: Debt,
    ui_port_opt: Option<u16>,
}

pub struct AssertionsValues {
    pub final_consuming_node_transaction_fee_balance_minor: u128,
    pub final_consuming_node_service_fee_balance_minor: u128,
    pub final_service_fee_balances_by_serving_nodes: FinalServiceFeeBalancesByServingNodes,
}

pub struct FinalServiceFeeBalancesByServingNodes {
    balances: [u128; 3],
}

impl FinalServiceFeeBalancesByServingNodes {
    pub fn new(node_1: u128, node_2: u128, node_3: u128) -> Self {
        let balances = [node_1, node_2, node_3];
        Self {
            balances,
        }
    }
}

pub struct BlockchainParams {
    chain: Chain,
    server_url: String,
    contract_owner_addr: Address,
    contract_owner_wallet: Wallet,
    seed: Seed,
}

struct BlockchainInterfaces {
    standard_blockchain_interface: Box<dyn BlockchainInterface>,
    web3: Web3<Http>,
}

pub struct GlobalValues {
    pub test_inputs: TestInputs,
    pub blockchain_params: BlockchainParams,
    pub now_in_common: SystemTime,
    blockchain_interfaces: BlockchainInterfaces,
}

pub struct WholesomeConfig {
    pub global_values: GlobalValues,
    pub consuming_node: ConsumingNode,
    pub serving_nodes: [ServingNode; 3],
}

pub struct DebtsSpecs {
    debts: [Debt; 3],
}

impl DebtsSpecs {
    pub fn new(node_1: Debt, node_2: Debt, node_3: Debt) -> Self {
        let debts = [node_1, node_2, node_3];
        Self { debts }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Debt {
    pub balance_minor: u128,
    pub age_s: u64,
}

impl Debt {
    pub fn new(balance_minor: u128, age_s: u64) -> Self {
        Self {
            balance_minor,
            age_s,
        }
    }

    fn proper_timestamp(&self, now: SystemTime) -> SystemTime {
        now.checked_sub(Duration::from_secs(self.age_s)).unwrap()
    }
}

pub trait NodeProfile {
    fn ui_port(&self) -> Option<u16>;

    fn debt_specs(&self) -> Debt;

    fn derivation_path(&self) -> String;

    fn name(&self) -> String;

    fn gas_price_opt(&self) -> Option<u64>;
}

impl NodeProfile for ConsumingNodeProfile {
    fn ui_port(&self) -> Option<u16> {
        self.ui_port_opt
    }

    fn debt_specs(&self) -> Debt {
        panic!("This method should be called only by the serving Nodes.")
    }

    fn derivation_path(&self) -> String {
        derivation_path(0, 1)
    }

    fn name(&self) -> String {
        "ConsumingNode".to_string()
    }

    fn gas_price_opt(&self) -> Option<u64> {
        self.gas_price_opt
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ServingNodeByName {
    ServingNode1 = 1,
    ServingNode2 = 2,
    ServingNode3 = 3,
}

impl NodeProfile for ServingNodeProfile {
    fn ui_port(&self) -> Option<u16> {
        self.ui_port_opt
    }

    fn debt_specs(&self) -> Debt {
        self.debt
    }

    fn derivation_path(&self) -> String {
        derivation_path(0, (self.serving_node_by_name as usize + 1) as u8)
    }

    fn name(&self) -> String {
        format!("{:?}", self.serving_node_by_name)
    }

    fn gas_price_opt(&self) -> Option<u64> {
        None
    }
}

pub fn establish_test_frame(
    test_inputs: TestInputs,
) -> (MASQNodeCluster, GlobalValues, BlockchainServer) {
    let now = SystemTime::now();
    let cluster = match MASQNodeCluster::start() {
        Ok(cluster) => cluster,
        Err(e) => panic!("{}", e),
    };
    let blockchain_server = BlockchainServer::new("ganache-cli");
    blockchain_server.start();
    blockchain_server.wait_until_ready();
    let server_url = blockchain_server.url().to_string();
    let (event_loop_handle, http) =
        Http::with_max_parallel(&server_url, REQUESTS_IN_PARALLEL).unwrap();
    let web3 = Web3::new(http.clone());
    let seed = make_seed();
    let (contract_owner_wallet, _) =
        make_node_wallet_and_private_key(&seed, &derivation_path(0, 0));
    let chain = cluster.chain();
    let contract_owner_addr = deploy_smart_contract(&contract_owner_wallet, &web3, chain);
    let blockchain_interface =
        Box::new(BlockchainInterfaceWeb3::new(http, event_loop_handle, chain));
    let blockchain_params = BlockchainParams {
        chain,
        server_url,
        contract_owner_addr,
        contract_owner_wallet,
        seed,
    };
    let blockchain_interfaces = BlockchainInterfaces {
        standard_blockchain_interface: blockchain_interface,
        web3,
    };
    let global_values = GlobalValues {
        test_inputs,
        blockchain_params,
        blockchain_interfaces,
        now_in_common: now,
    };
    assert_eq!(
        contract_owner_addr,
        chain.rec().contract,
        "Either the contract has been modified or Ganache is not accurately mimicking Ethereum. \
         Resulted contact addr {:?} doesn't much what's expected: {:?}",
        contract_owner_addr,
        chain.rec().contract
    );

    (cluster, global_values, blockchain_server)
}

fn make_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(MNEMONIC_PHRASE, Language::English).unwrap();
    Seed::new(&mnemonic, "")
}

pub fn to_wei(gwei: u64) -> u128 {
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

lazy_static! {
    static ref GAS_PRICE: ethereum_types::U256 =
        50_u64.try_into().expect("Gas price, internal error");
    static ref GAS_LIMIT: ethereum_types::U256 =
        1_000_000_u64.try_into().expect("Gas limit, internal error");
}

fn deploy_smart_contract(wallet: &Wallet, web3: &Web3<Http>, chain: Chain) -> Address {
    let contract = load_contract_in_bytes();
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::zero()),
        to: None,
        gas: *GAS_LIMIT,
        gas_price: Some(*GAS_PRICE),
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
            Ok(Some(tx_receipt)) => tx_receipt.contract_address.unwrap(),
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
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::try_from(transaction_nonce).expect("Internal error")),
        to: Some(contract_addr),
        gas: *GAS_LIMIT,
        gas_price: Some(*GAS_PRICE),
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
    let secret = &signing_wallet
        .prepare_secp256k1_secret()
        .expect("wallet without secret");
    web3.accounts()
        .sign_transaction(tx, secret)
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
    let tx = TransactionRequest {
        from: from_wallet.address(),
        to: Some(to_wallet.address()),
        gas: Some(*GAS_LIMIT),
        gas_price: Some(*GAS_PRICE),
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
    single_balance_assertion(
        blockchain_interface,
        wallet,
        expected_eth_balance,
        "ETH balance",
        |blockchain_interface, wallet| blockchain_interface.get_transaction_fee_balance(wallet),
    );

    single_balance_assertion(
        blockchain_interface,
        wallet,
        expected_token_balance,
        "MASQ balance",
        |blockchain_interface, wallet| blockchain_interface.get_service_fee_balance(wallet),
    );
}

fn single_balance_assertion(
    blockchain_interface: &dyn BlockchainInterface,
    wallet: &Wallet,
    expected_balance: u128,
    balance_specification: &str,
    balance_fetcher: fn(&dyn LowBlockchainInt, &Wallet) -> ResultForBalance,
) {
    let actual_balance = {
        let lower_blockchain_int = blockchain_interface.lower_interface();
        balance_fetcher(lower_blockchain_int, &wallet).unwrap_or_else(|_| {
            panic!(
                "Failed to retrieve {} for {}",
                balance_specification, wallet
            )
        })
    };
    assert_eq!(
        actual_balance,
        web3::types::U256::from(expected_balance),
        "Actual {} {} doesn't much with expected {} for {}",
        balance_specification,
        actual_balance,
        expected_balance,
        wallet
    );
}

fn make_node_wallet_and_private_key(seed: &Seed, derivation_path: &str) -> (Wallet, String) {
    let extended_private_key = ExtendedPrivKey::derive(&seed.as_ref(), derivation_path).unwrap();
    let str_private_key: String = extended_private_key.secret().to_hex();
    let wallet = Wallet::from(Bip32EncryptionKeyProvider::from_key(extended_private_key));
    (wallet, str_private_key)
}

impl GlobalValues {
    fn get_node_config_and_wallet(&self, node: &dyn NodeProfile) -> (NodeStartupConfig, Wallet) {
        let wallet_derivation_path = node.derivation_path();
        let payment_thresholds = self.test_inputs.payment_thresholds_all_nodes;
        let (node_wallet, node_secret) = make_node_wallet_and_private_key(
            &self.blockchain_params.seed,
            wallet_derivation_path.as_str(),
        );
        let mut config_builder = NodeStartupConfigBuilder::standard()
            .blockchain_service_url(&self.blockchain_params.server_url)
            .chain(Chain::Dev)
            .payment_thresholds(payment_thresholds)
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(node_secret))
            .earning_wallet_info(EarningWalletInfo::Address(format!(
                "{}",
                node_wallet.clone()
            )));
        if let Some(port) = node.ui_port() {
            config_builder = config_builder.ui_port(port)
        }
        if let Some(gas_price) = node.gas_price_opt() {
            config_builder = config_builder.gas_price(gas_price)
        }
        eprintln!("{} wallet established: {}\n", node.name(), node_wallet,);
        (config_builder.build(), node_wallet)
    }

    fn prepare_consuming_node(
        &self,
        cluster: &mut MASQNodeCluster,
        blockchain_interfaces: &BlockchainInterfaces,
    ) -> ConsumingNode {
        let consuming_node_profile = self.test_inputs.node_profiles.consuming_node.clone();
        let initial_service_fee_balance_minor =
            consuming_node_profile.initial_service_fee_balance_minor;
        let initial_tx_fee_balance_opt = consuming_node_profile.initial_tx_fee_balance_minor_opt;

        let (consuming_node_config, consuming_node_wallet) =
            self.get_node_config_and_wallet(&consuming_node_profile);
        let initial_transaction_fee_balance = initial_tx_fee_balance_opt.unwrap_or(ONE_ETH_IN_WEI);
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
            initial_service_fee_balance_minor,
            2,
            &blockchain_interfaces.web3,
            self.blockchain_params.chain,
        );

        assert_balances(
            &consuming_node_wallet,
            blockchain_interfaces.standard_blockchain_interface.as_ref(),
            initial_transaction_fee_balance,
            initial_service_fee_balance_minor,
        );

        let prepared_node = cluster.prepare_real_node(&consuming_node_config);
        let consuming_node_connection = DbInitializerReal::default()
            .initialize(&prepared_node.db_path, make_db_init_config(cluster.chain()))
            .unwrap();
        let consuming_node_payable_dao = PayableDaoReal::new(consuming_node_connection);
        open_all_file_permissions(&prepared_node.db_path);
        ConsumingNode::new(
            consuming_node_profile,
            prepared_node,
            consuming_node_config,
            consuming_node_wallet,
            consuming_node_payable_dao,
        )
    }

    fn prepare_serving_nodes(&self, cluster: &mut MASQNodeCluster) -> [ServingNode; 3] {
        self.test_inputs
            .node_profiles
            .serving_nodes
            .clone()
            .into_iter()
            .map(|serving_node_profile: ServingNodeProfile| {
                let (serving_node_config, serving_node_earning_wallet) =
                    self.get_node_config_and_wallet(&serving_node_profile);
                let prepared_node_info = cluster.prepare_real_node(&serving_node_config);
                let serving_node_connection = DbInitializerReal::default()
                    .initialize(
                        &prepared_node_info.db_path,
                        make_db_init_config(cluster.chain()),
                    )
                    .unwrap();
                let serving_node_receivable_dao = ReceivableDaoReal::new(serving_node_connection);
                open_all_file_permissions(&prepared_node_info.db_path);
                ServingNode::new(
                    serving_node_profile,
                    prepared_node_info,
                    serving_node_config,
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

    fn set_up_serving_nodes_databases(
        &self,
        serving_nodes_array: &[ServingNode; 3],
        consuming_node: &ConsumingNode,
    ) {
        let now = self.now_in_common;
        serving_nodes_array.iter().for_each(|serving_node| {
            let (balance, timestamp) = serving_node.debt_balance_and_timestamp(now);
            serving_node
                .receivable_dao
                .more_money_receivable(timestamp, &consuming_node.consuming_wallet, balance)
                .unwrap();
            assert_balances(
                &serving_node.earning_wallet,
                self.blockchain_interfaces
                    .standard_blockchain_interface
                    .as_ref(),
                0,
                0,
            );
            Self::set_start_block_to_zero(&serving_node.common.prepared_node.db_path)
        })
    }

    fn set_up_consuming_node_db(
        &self,
        serving_nodes_array: &[ServingNode; 3],
        consuming_node: &ConsumingNode,
    ) {
        let now = self.now_in_common;
        serving_nodes_array.iter().for_each(|serving_node| {
            let (balance, timestamp) = serving_node.debt_balance_and_timestamp(now);
            consuming_node
                .payable_dao
                .more_money_payable(timestamp, &serving_node.earning_wallet, balance)
                .unwrap();
        });
        Self::set_start_block_to_zero(&consuming_node.common.prepared_node.db_path)
    }
}

impl WholesomeConfig {
    fn new(
        global_values: GlobalValues,
        consuming_node: ConsumingNode,
        serving_nodes: [ServingNode; 3],
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
        .for_each(|(expected_wallet_addr, serving_node)| {
            let serving_node_actual = serving_node.earning_wallet.to_string();
            assert_eq!(
                &serving_node_actual,
                expected_wallet_addr,
                "{:?} wallet {} mismatched with expected {}",
                serving_node.serving_node_profile.serving_node_by_name,
                serving_node_actual,
                expected_wallet_addr
            );
        })
    }

    fn assert_payments_via_direct_blockchain_scanning(&self, assertions_values: &AssertionsValues) {
        let blockchain_interface = self
            .global_values
            .blockchain_interfaces
            .standard_blockchain_interface
            .as_ref();
        assert_balances(
            &self.consuming_node.consuming_wallet,
            blockchain_interface,
            assertions_values.final_consuming_node_transaction_fee_balance_minor,
            assertions_values.final_consuming_node_service_fee_balance_minor,
        );
        assertions_values
            .final_service_fee_balances_by_serving_nodes
            .balances
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
        let actually_received_payments = assertions_values
            .final_service_fee_balances_by_serving_nodes
            .balances;
        let consuming_node_wallet = &self.consuming_node.consuming_wallet;
        self.serving_nodes
            .iter()
            .zip(actually_received_payments.into_iter())
            .for_each(|(serving_node, received_payment)| {
                let original_debt = serving_node.serving_node_profile.debt_specs().balance_minor;
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

pub const ONE_ETH_IN_WEI: u128 = 10_u128.pow(18);

pub struct Ports {
    consuming_node: u16,
    serving_nodes: [u16; 3],
}

impl Ports {
    pub fn new(
        consuming_node: u16,
        serving_node_1: u16,
        serving_node_2: u16,
        serving_node_3: u16,
    ) -> Self {
        Self {
            consuming_node,
            serving_nodes: [serving_node_1, serving_node_2, serving_node_3],
        }
    }
}

#[derive(Debug)]
pub struct NodeAttributesCommon {
    pub prepared_node: PreparedNodeInfo,
    pub startup_config_opt: RefCell<Option<NodeStartupConfig>>,
}

impl NodeAttributesCommon {
    fn new(prepared_node: PreparedNodeInfo, config: NodeStartupConfig) -> Self {
        NodeAttributesCommon {
            prepared_node,
            startup_config_opt: RefCell::new(Some(config)),
        }
    }
}

#[derive(Debug)]
pub struct ConsumingNode {
    pub node_profile: ConsumingNodeProfile,
    pub common: NodeAttributesCommon,
    pub consuming_wallet: Wallet,
    pub payable_dao: PayableDaoReal,
}

#[derive(Debug)]
pub struct ServingNode {
    pub serving_node_profile: ServingNodeProfile,
    pub common: NodeAttributesCommon,
    pub earning_wallet: Wallet,
    pub receivable_dao: ReceivableDaoReal,
}

impl ServingNode {
    fn debt_balance_and_timestamp(&self, now: SystemTime) -> (u128, SystemTime) {
        let debt_specs = self.serving_node_profile.debt_specs();
        (debt_specs.balance_minor, debt_specs.proper_timestamp(now))
    }
}

impl ConsumingNode {
    fn new(
        node_profile: ConsumingNodeProfile,
        prepared_node: PreparedNodeInfo,
        config: NodeStartupConfig,
        consuming_wallet: Wallet,
        payable_dao: PayableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon::new(prepared_node, config);
        Self {
            node_profile,
            common,
            consuming_wallet,
            payable_dao,
        }
    }
}

impl ServingNode {
    fn new(
        serving_node_profile: ServingNodeProfile,
        prepared_node: PreparedNodeInfo,
        config: NodeStartupConfig,
        earning_wallet: Wallet,
        receivable_dao: ReceivableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon::new(prepared_node, config);
        Self {
            serving_node_profile,
            common,
            earning_wallet,
            receivable_dao,
        }
    }
}
