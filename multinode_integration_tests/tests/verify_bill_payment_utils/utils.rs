// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use bip39::{Language, Mnemonic, Seed};
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::{derivation_path, NeighborhoodModeLight};
use multinode_integration_tests_lib::blockchain::BlockchainServer;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, EarningWalletInfo, MASQRealNode, NodeID, NodeStartupConfig,
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
use node_lib::sub_lib::blockchain_interface_web3::transaction_data_web3;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils;
use node_lib::test_utils::standard_dir_for_test_input_data;
use rustc_hex::{FromHex, ToHex};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use lazy_static::lazy_static;
use tiny_hderive::bip32::ExtendedPrivKey;
use web3::transports::Http;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, TransactionRequest};
use web3::Web3;

pub type StimulateConsumingNodePayments =
    fn(&mut MASQNodeCluster, &MASQRealNode, &GlobalValues);

pub type StartServingNodesAndLetThemPerformReceivablesCheck = fn(
    &mut MASQNodeCluster,
    &mut [ServingNodeAttributes; 3],
    &GlobalValues,
) -> [MASQRealNode; 3];

pub fn test_body(
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
        &wholesome_config.consuming_node.common.node_id.node_name,
        wholesome_config.consuming_node.common.node_id.index,
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

const MNEMONIC_PHRASE: &str =
    "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle \
    lamp absent write kind term toddler sphere ripple idle dragon curious hold";

pub struct TestInputs {
    ui_ports_opt: Option<Ports>,
    // The contract owner wallet is populated with 100 ETH as defined in the set of commands
    // with which we start up the Ganache server.
    //
    // Specify number of wei this account should possess at its initialisation.
    // The consuming node gets the full balance of the contract owner if left as None.
    // Cannot ever get more than what the "owner" has.
    consuming_node_initial_tx_fee_balance_minor_opt: Option<u128>,
    consuming_node_initial_service_fee_balance_minor: u128,
    debts_config: DebtsSpecs,
    payment_thresholds_all_nodes: PaymentThresholds,
    consuming_node_gas_price_opt: Option<u64>,
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
        TestInputs{
            ui_ports_opt: self.ui_ports_opt,
            consuming_node_initial_tx_fee_balance_minor_opt: self.consuming_node_initial_tx_fee_balance_minor_opt,
            consuming_node_initial_service_fee_balance_minor: self.consuming_node_initial_service_fee_balance_minor_opt.expect("You forgot providing a mandatory input: consuming node initial service fee balance"),
            debts_config: self.debts_config_opt.expect("You forgot providing a mandatory input: debts config"),
            payment_thresholds_all_nodes: self.payment_thresholds_all_nodes_opt.expect("You forgot providing a mandatory input: payment thresholds"),
            consuming_node_gas_price_opt: self.consuming_node_gas_price_opt,
        }
    }
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
        Self {
            balances: [node_1, node_2, node_3],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeByRole {
    ConsumingNode = 1,
    ServingNode1 = 2,
    ServingNode2 = 3,
    ServingNode3 = 4,
}

pub struct BlockchainParams {
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

pub struct GlobalValues {
    pub test_inputs: TestInputs,
    pub blockchain_params: BlockchainParams,
    pub now_in_common: SystemTime,
}

pub struct WholesomeConfig {
    pub global_values: GlobalValues,
    pub consuming_node: ConsumingNodeAttributes,
    pub serving_nodes: [ServingNodeAttributes; 3],
}

pub struct DebtsSpecs {
    debts: [Debt; 3],
}

impl DebtsSpecs {
    pub fn new(node_1: Debt, node_2: Debt, node_3: Debt) -> Self {
        Self {
            debts: [node_1, node_2, node_3],
        }
    }
}

#[derive(Copy, Clone)]
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

impl TestInputs {
    pub fn port(&self, requested: NodeByRole) -> Option<u16> {
        self.ui_ports_opt.as_ref().map(|ports| match requested {
            NodeByRole::ConsumingNode => ports.consuming_node,
            NodeByRole::ServingNode1 => ports.serving_nodes[0],
            NodeByRole::ServingNode2 => ports.serving_nodes[1],
            NodeByRole::ServingNode3 => ports.serving_nodes[2],
        })
    }

    pub fn debt_specs(&self, requested: NodeByRole) -> Debt {
        match requested {
            NodeByRole::ServingNode1 => self.debts_config.debts[0],
            NodeByRole::ServingNode2 => self.debts_config.debts[1],
            NodeByRole::ServingNode3 => self.debts_config.debts[2],
            NodeByRole::ConsumingNode => panic!(
                "Version fully specified: These configs describe debts owed to the consuming node, \
                while that one should not be here."
            ),
        }
    }
}

pub fn establish_test_frame(test_inputs: TestInputs) -> (MASQNodeCluster, GlobalValues) {
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
    let (contract_owner_wallet, _) = make_node_wallet_and_private_key(&seed, &derivation_path(0, 0));
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
    static ref GAS_PRICE: ethereum_types::U256 = 50_u64.try_into().expect("Gas price, internal error");
    static ref GAS_LIMIT: ethereum_types::U256 = 1_000_000_u64.try_into().expect("Gas limit, internal error");
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

fn make_node_wallet_and_private_key(seed: &Seed, derivation_path: &str) -> (Wallet, String) {
    let extended_private_key = ExtendedPrivKey::derive(&seed.as_ref(), derivation_path).unwrap();
    let str_private_key: String = extended_private_key.secret().to_hex();
    let wallet = Wallet::from(Bip32EncryptionKeyProvider::from_key(extended_private_key));
    (
        wallet,
        str_private_key,
    )
}

impl GlobalValues {
    fn get_node_config_and_wallet(&self, node_by_role: NodeByRole) -> (NodeStartupConfig, Wallet) {
        let wallet_derivation_path = node_by_role.derivation_path();
        let payment_thresholds = self.test_inputs.payment_thresholds_all_nodes;
        let (node_wallet, node_secret) = make_node_wallet_and_private_key(
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
            .consuming_node_initial_tx_fee_balance_minor_opt
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
            Self::set_start_block_to_zero(&node_attributes.common.node_id.db_path)
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
        Self::set_start_block_to_zero(&consuming_node_attributes.common.node_id.db_path)
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
                let original_debt = self
                    .global_values
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

impl NodeByRole {
    fn derivation_path(self) -> String {
        derivation_path(0, self as usize as u8)
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
    pub node_by_role: NodeByRole,
    pub node_id: NodeID,
    pub config_opt: Option<NodeStartupConfig>,
}

#[derive(Debug)]
pub struct ConsumingNodeAttributes {
    pub common: NodeAttributesCommon,
    pub consuming_wallet: Wallet,
    pub payable_dao: PayableDaoReal,
}

#[derive(Debug)]
pub struct ServingNodeAttributes {
    pub common: NodeAttributesCommon,
    pub earning_wallet: Wallet,
    pub receivable_dao: ReceivableDaoReal,
}

impl ConsumingNodeAttributes {
    fn new(
        node_by_role: NodeByRole,
        node_id: NodeID,
        config_opt: Option<NodeStartupConfig>,
        consuming_wallet: Wallet,
        payable_dao: PayableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon {
            node_by_role,
            node_id,
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
        node_id: NodeID,
        config_opt: Option<NodeStartupConfig>,
        earning_wallet: Wallet,
        receivable_dao: ReceivableDaoReal,
    ) -> Self {
        let common = NodeAttributesCommon {
            node_by_role,
            node_id,
            config_opt,
        };
        Self {
            common,
            earning_wallet,
            receivable_dao,
        }
    }
}
