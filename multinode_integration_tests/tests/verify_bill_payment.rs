// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use bip39::{Language, Mnemonic, Seed};
use futures::Future;
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use masq_lib::messages::FromMessageBody;
use masq_lib::messages::ToMessageBody;
use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
use masq_lib::percentage::Percentage;
use masq_lib::utils::{derivation_path, find_free_port, NeighborhoodModeLight};
use multinode_integration_tests_lib::blockchain::BlockchainServer;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, EarningWalletInfo, MASQRealNode, NodeStartupConfig,
    NodeStartupConfigBuilder,
};
use multinode_integration_tests_lib::utils::{
    node_chain_specific_data_directory, open_all_file_permissions, UrlHolder,
};
use node_lib::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::accountant::db_access_objects::utils::to_time_t;
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
use rusqlite::ToSql;
use rustc_hex::{FromHex, ToHex};
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use std::{thread, u128};
use tiny_hderive::bip32::ExtendedPrivKey;
use web3::transports::Http;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, TransactionRequest};
use web3::Web3;

#[test]
fn verify_bill_payment() {
    // Note: besides the main objectives of this test, it relies on (and so it proves) the premise
    // that each Node, after it reaches its full connectivity and becomes able to make a route,
    // activates its accountancy module whereas it also unleashes the first cycle of the scanners
    // immediately. That's why some consideration has been made not to take out the passage with
    // the intense startups of a bunch of Nodes, with that particular reason to fulfill the above
    // depicted scenario, even though this test could be written more simply with the use of
    // the `scans` command emitted from a UI, with a smaller PCU burden. (You may want to know that
    // such an approach is implemented for another test in this file.)
    let payment_thresholds = PaymentThresholds {
        threshold_interval_sec: 2_500_000,
        debt_threshold_gwei: 1_000_000_000,
        payment_grace_period_sec: 85_000,
        maturity_threshold_sec: 85_000,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_below_gwei: 10_000_000,
    };
    let owed_to_serving_node_1_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei) + 123_456;
    let owed_to_serving_node_2_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei) + 456_789;
    let owed_to_serving_node_3_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei) + 789_012;
    let cons_node_initial_service_fee_balance_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei) * 4;
    let exp_final_cons_node_service_fee_balance_minor = cons_node_initial_service_fee_balance_minor
        - (owed_to_serving_node_1_minor
            + owed_to_serving_node_2_minor
            + owed_to_serving_node_3_minor);
    let test_global_config = TestInputsOutputsConfig {
        ui_ports_opt: None,
        cons_node_initial_transaction_fee_balance_minor_opt: None,
        cons_node_initial_service_fee_balance_minor,
        debts_config: Either::Left(SimpleSimulatedDebts {
            owed_to_serving_node_1_minor,
            owed_to_serving_node_2_minor,
            owed_to_serving_node_3_minor,
        }),
        payment_thresholds_all_nodes: payment_thresholds,
        cons_node_transaction_fee_agreed_unit_price_opt: None,
        exp_final_cons_node_transaction_fee_balance_minor: 999_842_470_000_000_000,
        exp_final_cons_node_service_fee_balance_minor,
        exp_final_service_fee_balance_serv_node_1_minor: owed_to_serving_node_1_minor,
        exp_final_service_fee_balance_serv_node_2_minor: owed_to_serving_node_2_minor,
        exp_final_service_fee_balance_serv_node_3_minor: owed_to_serving_node_3_minor,
    };

    let stimulate_payments =
        |cluster: &mut MASQNodeCluster,
         real_consuming_node: &MASQRealNode,
         _global_test_config: &TestInputsOutputsConfig| {
            for _ in 0..6 {
                cluster.start_real_node(
                    NodeStartupConfigBuilder::standard()
                        .chain(Chain::Dev)
                        .neighbor(real_consuming_node.node_reference())
                        .build(),
                );
            }
        };

    let start_serving_nodes_and_run_check =
        |cluster: &mut MASQNodeCluster,
         serving_node_1_attributes: ServingNodeAttributes,
         serving_node_2_attributes: ServingNodeAttributes,
         serving_node_3_attributes: ServingNodeAttributes,
         _test_global_config: &TestInputsOutputsConfig| {
            let serving_node_1 = cluster.start_named_real_node(
                &serving_node_1_attributes.name,
                serving_node_1_attributes.index,
                serving_node_1_attributes.config,
            );
            let serving_node_2 = cluster.start_named_real_node(
                &serving_node_2_attributes.name,
                serving_node_2_attributes.index,
                serving_node_2_attributes.config,
            );
            let serving_node_3 = cluster.start_named_real_node(
                &serving_node_3_attributes.name,
                serving_node_3_attributes.index,
                serving_node_3_attributes.config,
            );
            for _ in 0..6 {
                cluster.start_real_node(
                    NodeStartupConfigBuilder::standard()
                        .chain(Chain::Dev)
                        .neighbor(serving_node_1.node_reference())
                        .neighbor(serving_node_2.node_reference())
                        .neighbor(serving_node_3.node_reference())
                        .build(),
                );
            }

            (serving_node_1, serving_node_2, serving_node_3)
        };

    test_body(
        test_global_config,
        stimulate_payments,
        start_serving_nodes_and_run_check,
    );
}

#[test]
fn payments_were_adjusted_due_to_insufficient_balances() {
    let consuming_node_ui_port = find_free_port();
    let serving_node_1_ui_port = find_free_port();
    let serving_node_2_ui_port = find_free_port();
    let serving_node_3_ui_port = find_free_port();
    let payment_thresholds = PaymentThresholds {
        threshold_interval_sec: 2_500_000,
        debt_threshold_gwei: 100_000_000,
        payment_grace_period_sec: 85_000,
        maturity_threshold_sec: 85_000,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_below_gwei: 1_000_000,
    };
    let owed_to_serv_node_1_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei + 5_000_000);
    let owed_to_serv_node_2_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei + 20_000_000);
    let owed_to_serv_node_3_minor =
        gwei_to_wei::<u128, _>(payment_thresholds.debt_threshold_gwei + 60_000_000);
    // Assuming all Nodes rely on the same set of payment thresholds
    let cons_node_initial_service_fee_balance_minor = (owed_to_serv_node_1_minor
        + owed_to_serv_node_2_minor)
        - gwei_to_wei::<u128, u64>(2_345_678);
    let agreed_transaction_fee_unit_price_major = 60;
    let transaction_fee_needed_to_pay_for_one_payment_major = {
        // We will need less but this should be accurate enough
        let txn_data_with_maximized_cost = [0xff; 68];
        let gas_limit_dev_chain = {
            let const_part = web3_gas_limit_const_part(Chain::Dev);
            u64::try_from(compute_gas_limit(
                const_part,
                txn_data_with_maximized_cost.as_slice(),
            ))
            .unwrap()
        };
        let transaction_fee_margin = Percentage::new(15);
        transaction_fee_margin
            .add_percent_to(gas_limit_dev_chain * agreed_transaction_fee_unit_price_major)
    };
    eprintln!(
        "Computed transaction fee: {}",
        transaction_fee_needed_to_pay_for_one_payment_major
    );
    let cons_node_transaction_fee_balance_minor =
        2 * gwei_to_wei::<u128, u64>(transaction_fee_needed_to_pay_for_one_payment_major);
    let test_global_config = TestInputsOutputsConfig {
        ui_ports_opt: Some(Ports {
            consuming_node: consuming_node_ui_port,
            serving_node_1: serving_node_1_ui_port,
            serving_node_2: serving_node_2_ui_port,
            serving_node_3: serving_node_3_ui_port,
        }),
        // Should be enough only for two payments, the least significant one will fall out
        cons_node_initial_transaction_fee_balance_minor_opt: Some(
            cons_node_transaction_fee_balance_minor + 1,
        ),
        cons_node_initial_service_fee_balance_minor,
        debts_config: Either::Right(FullySpecifiedSimulatedDebts {
            // This account will be the most significant and will deserve the full balance
            owed_to_serving_node_1: AccountedDebt {
                balance_minor: owed_to_serv_node_1_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 1000,
            },
            // This balance is of a middle size it will be reduced as there won't be enough
            // after the first one is filled up.
            owed_to_serving_node_2: AccountedDebt {
                balance_minor: owed_to_serv_node_2_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 100_000,
            },
            // This account will be the least significant and therefore eliminated
            owed_to_serving_node_3: AccountedDebt {
                balance_minor: owed_to_serv_node_3_minor,
                age_s: payment_thresholds.maturity_threshold_sec + 30_000,
            },
        }),
        payment_thresholds_all_nodes: payment_thresholds,
        cons_node_transaction_fee_agreed_unit_price_opt: Some(
            agreed_transaction_fee_unit_price_major,
        ),
        // It seems like the ganache server sucked up quite less than those 55_000 units of gas??
        exp_final_cons_node_transaction_fee_balance_minor: 2_828_352_000_000_001,
        // Zero reached, because the algorithm is designed to exhaust the wallet completely
        exp_final_cons_node_service_fee_balance_minor: 0,
        // This account was granted with the full size as its lowest balance from the set makes
        // it weight the most
        exp_final_service_fee_balance_serv_node_1_minor: owed_to_serv_node_1_minor,
        exp_final_service_fee_balance_serv_node_2_minor: owed_to_serv_node_2_minor
            - gwei_to_wei::<u128, u64>(2_345_678),
        // This account dropped out from the payment, so received no money
        exp_final_service_fee_balance_serv_node_3_minor: 0,
    };

    let process_scan_request_to_node =
        |real_node: &MASQRealNode, ui_port: u16, scan_type: ScanType, context_id: u64| {
            let ui_client = real_node.make_ui(ui_port);
            ui_client.send_request(UiScanRequest { scan_type }.tmb(context_id));
            let response = ui_client.wait_for_response(context_id, Duration::from_secs(10));
            UiScanResponse::fmb(response).unwrap();
        };

    let stimulate_payments =
        |_cluster: &mut MASQNodeCluster,
         real_consuming_node: &MASQRealNode,
         _global_test_config: &TestInputsOutputsConfig| {
            process_scan_request_to_node(
                &real_consuming_node,
                consuming_node_ui_port,
                ScanType::Payables,
                1111,
            )
        };

    let start_serving_nodes_and_run_check = |cluster: &mut MASQNodeCluster,
                                             serving_node_1_attributes: ServingNodeAttributes,
                                             serving_node_2_attributes: ServingNodeAttributes,
                                             serving_node_3_attributes: ServingNodeAttributes,
                                             test_global_config: &TestInputsOutputsConfig|
     -> (MASQRealNode, MASQRealNode, MASQRealNode) {
        let ports = test_global_config.ui_ports_opt.as_ref().unwrap();
        let mut vec: Vec<MASQRealNode> = vec![
            (serving_node_1_attributes, ports.serving_node_1, 2222),
            (serving_node_2_attributes, ports.serving_node_2, 3333),
            (serving_node_3_attributes, ports.serving_node_3, 4444),
        ]
        .into_iter()
        .map(|(serving_node_attributes, ui_port, context_id)| {
            let serving_node = cluster.start_named_real_node(
                &serving_node_attributes.name,
                serving_node_attributes.index,
                serving_node_attributes.config,
            );

            process_scan_request_to_node(&serving_node, ui_port, ScanType::Receivables, context_id);

            serving_node
        })
        .collect();
        (vec.remove(0), vec.remove(0), vec.remove(0))
    };

    test_body(
        test_global_config,
        stimulate_payments,
        start_serving_nodes_and_run_check,
    );
}

fn make_init_config(chain: Chain) -> DbInitializationConfig {
    DbInitializationConfig::create_or_migrate(ExternalData::new(
        chain,
        NeighborhoodModeLight::Standard,
        None,
    ))
}

fn deploy_smart_contract(wallet: &Wallet, web3: &Web3<Http>, chain: Chain) -> Address {
    let data = "608060405234801561001057600080fd5b5060038054600160a060020a031916331790819055604051600160a060020a0391909116906000907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908290a3610080336b01866de34549d620d8000000640100000000610b9461008582021704565b610156565b600160a060020a038216151561009a57600080fd5b6002546100b490826401000000006109a461013d82021704565b600255600160a060020a0382166000908152602081905260409020546100e790826401000000006109a461013d82021704565b600160a060020a0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b60008282018381101561014f57600080fd5b9392505050565b610c6a806101656000396000f3006080604052600436106100fb5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166306fdde038114610100578063095ea7b31461018a57806318160ddd146101c257806323b872dd146101e95780632ff2e9dc14610213578063313ce56714610228578063395093511461025357806342966c681461027757806370a0823114610291578063715018a6146102b257806379cc6790146102c75780638da5cb5b146102eb5780638f32d59b1461031c57806395d89b4114610331578063a457c2d714610346578063a9059cbb1461036a578063dd62ed3e1461038e578063f2fde38b146103b5575b600080fd5b34801561010c57600080fd5b506101156103d6565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561014f578181015183820152602001610137565b50505050905090810190601f16801561017c5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561019657600080fd5b506101ae600160a060020a0360043516602435610436565b604080519115158252519081900360200190f35b3480156101ce57600080fd5b506101d7610516565b60408051918252519081900360200190f35b3480156101f557600080fd5b506101ae600160a060020a036004358116906024351660443561051c565b34801561021f57600080fd5b506101d76105b9565b34801561023457600080fd5b5061023d6105c9565b6040805160ff9092168252519081900360200190f35b34801561025f57600080fd5b506101ae600160a060020a03600435166024356105ce565b34801561028357600080fd5b5061028f60043561067e565b005b34801561029d57600080fd5b506101d7600160a060020a036004351661068b565b3480156102be57600080fd5b5061028f6106a6565b3480156102d357600080fd5b5061028f600160a060020a0360043516602435610710565b3480156102f757600080fd5b5061030061071e565b60408051600160a060020a039092168252519081900360200190f35b34801561032857600080fd5b506101ae61072d565b34801561033d57600080fd5b5061011561073e565b34801561035257600080fd5b506101ae600160a060020a0360043516602435610775565b34801561037657600080fd5b506101ae600160a060020a03600435166024356107c0565b34801561039a57600080fd5b506101d7600160a060020a03600435811690602435166107d6565b3480156103c157600080fd5b5061028f600160a060020a0360043516610801565b606060405190810160405280602481526020017f486f7420746865206e657720746f6b656e20796f75277265206c6f6f6b696e6781526020017f20666f720000000000000000000000000000000000000000000000000000000081525081565b600081158061044c575061044a33846107d6565b155b151561050557604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152604160248201527f55736520696e637265617365417070726f76616c206f7220646563726561736560448201527f417070726f76616c20746f2070726576656e7420646f75626c652d7370656e6460648201527f2e00000000000000000000000000000000000000000000000000000000000000608482015290519081900360a40190fd5b61050f838361081d565b9392505050565b60025490565b600160a060020a038316600090815260016020908152604080832033845290915281205482111561054c57600080fd5b600160a060020a0384166000908152600160209081526040808320338452909152902054610580908363ffffffff61089b16565b600160a060020a03851660009081526001602090815260408083203384529091529020556105af8484846108b2565b5060019392505050565b6b01866de34549d620d800000081565b601281565b6000600160a060020a03831615156105e557600080fd5b336000908152600160209081526040808320600160a060020a0387168452909152902054610619908363ffffffff6109a416565b336000818152600160209081526040808320600160a060020a0389168085529083529281902085905580519485525191937f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925929081900390910190a350600192915050565b61068833826109b6565b50565b600160a060020a031660009081526020819052604090205490565b6106ae61072d565b15156106b957600080fd5b600354604051600091600160a060020a0316907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908390a36003805473ffffffffffffffffffffffffffffffffffffffff19169055565b61071a8282610a84565b5050565b600354600160a060020a031690565b600354600160a060020a0316331490565b60408051808201909152600381527f484f540000000000000000000000000000000000000000000000000000000000602082015281565b6000600160a060020a038316151561078c57600080fd5b336000908152600160209081526040808320600160a060020a0387168452909152902054610619908363ffffffff61089b16565b60006107cd3384846108b2565b50600192915050565b600160a060020a03918216600090815260016020908152604080832093909416825291909152205490565b61080961072d565b151561081457600080fd5b61068881610b16565b6000600160a060020a038316151561083457600080fd5b336000818152600160209081526040808320600160a060020a03881680855290835292819020869055805186815290519293927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925929181900390910190a350600192915050565b600080838311156108ab57600080fd5b5050900390565b600160a060020a0383166000908152602081905260409020548111156108d757600080fd5b600160a060020a03821615156108ec57600080fd5b600160a060020a038316600090815260208190526040902054610915908263ffffffff61089b16565b600160a060020a03808516600090815260208190526040808220939093559084168152205461094a908263ffffffff6109a416565b600160a060020a038084166000818152602081815260409182902094909455805185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3505050565b60008282018381101561050f57600080fd5b600160a060020a03821615156109cb57600080fd5b600160a060020a0382166000908152602081905260409020548111156109f057600080fd5b600254610a03908263ffffffff61089b16565b600255600160a060020a038216600090815260208190526040902054610a2f908263ffffffff61089b16565b600160a060020a038316600081815260208181526040808320949094558351858152935191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929081900390910190a35050565b600160a060020a0382166000908152600160209081526040808320338452909152902054811115610ab457600080fd5b600160a060020a0382166000908152600160209081526040808320338452909152902054610ae8908263ffffffff61089b16565b600160a060020a038316600090815260016020908152604080832033845290915290205561071a82826109b6565b600160a060020a0381161515610b2b57600080fd5b600354604051600160a060020a038084169216907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a36003805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0392909216919091179055565b600160a060020a0382161515610ba957600080fd5b600254610bbc908263ffffffff6109a416565b600255600160a060020a038216600090815260208190526040902054610be8908263ffffffff6109a416565b600160a060020a0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a350505600a165627a7a72305820d4ad56dfe541fec48c3ecb02cebad565a998dfca7774c0c4f4b1f4a8e2363a590029".from_hex::<Vec<u8>>().unwrap();
    let gas_price = 50_000_000_000_u64;
    let gas_limit = 1_000_000_u64;
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::try_from(0).expect("Internal error")),
        to: None,
        gas: ethereum_types::U256::try_from(gas_limit).expect("Internal error"),
        gas_price: Some(ethereum_types::U256::try_from(gas_price).expect("Internal error")),
        value: ethereum_types::U256::zero(),
        data: Bytes(data),
        chain_id: Some(chain.rec().num_chain_id),
    };
    let signed_tx = sign_transaction(web3, tx, wallet);
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
    let gas_price = 150_000_000_000_u64;
    let gas_limit = 1_000_000_u64;
    let tx = TransactionParameters {
        nonce: Some(ethereum_types::U256::try_from(transaction_nonce).expect("Internal error")),
        to: Some(contract_addr),
        gas: ethereum_types::U256::try_from(gas_limit).expect("Internal error"),
        gas_price: Some(ethereum_types::U256::try_from(gas_price).expect("Internal error")),
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };

    let signed_tx = sign_transaction(web3, tx, from_wallet);

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

fn sign_transaction(
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
    let gas_price = 150_000_000_000_u64;
    let gas_limit = 1_000_000_u64;
    let tx = TransactionRequest {
        from: from_wallet.address(),
        to: Some(to_wallet.address()),
        gas: Some(ethereum_types::U256::try_from(gas_limit).expect("Internal error")),
        gas_price: Some(ethereum_types::U256::try_from(gas_price).expect("Internal error")),
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
    blockchain_interface: &BlockchainInterfaceWeb3<Http>,
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

fn make_seed() -> Seed {
    let phrase = "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp absent write kind term toddler sphere ripple idle dragon curious hold";
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");
    seed
}

fn build_config(
    server_url_holder: &dyn UrlHolder,
    seed: &Seed,
    payment_thresholds: PaymentThresholds,
    transaction_fee_agreed_price_per_unit_opt: Option<u64>,
    wallet_derivation_path: String,
    port_opt: Option<u16>,
) -> (NodeStartupConfig, Wallet) {
    let (node_wallet, node_secret) = make_node_wallet(seed, wallet_derivation_path.as_str());
    let cfg_to_build = NodeStartupConfigBuilder::standard()
        .blockchain_service_url(server_url_holder.url())
        .chain(Chain::Dev)
        .payment_thresholds(payment_thresholds)
        .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(node_secret))
        .earning_wallet_info(EarningWalletInfo::Address(format!(
            "{}",
            node_wallet.clone()
        )));
    let cfg_to_build = if let Some(port) = port_opt {
        cfg_to_build.ui_port(port)
    } else {
        cfg_to_build
    };
    let cfg_to_build = if let Some(price) = transaction_fee_agreed_price_per_unit_opt {
        cfg_to_build.gas_price(price)
    } else {
        cfg_to_build
    };
    let config = cfg_to_build.build();
    (config, node_wallet)
}

fn expire_payables(
    path: PathBuf,
    debts_config: &Either<SimpleSimulatedDebts, FullySpecifiedSimulatedDebts>,
    now: SystemTime,
    serving_node_1_wallet: &Wallet,
    serving_node_2_wallet: &Wallet,
    serving_node_3_wallet: &Wallet,
) {
    let conn = DbInitializerReal::default()
        .initialize(&path, DbInitializationConfig::panic_on_migration())
        .unwrap();
    match debts_config {
        Either::Left(_) => {
            let _ = conn
            .prepare(
                "update payable set last_paid_timestamp = 0 where pending_payable_rowid is null",
            )
            .unwrap()
            .execute([])
            .unwrap();
        }
        Either::Right(fully_specified_config) => vec![
            (
                serving_node_1_wallet,
                fully_specified_config.owed_to_serving_node_1.age_s,
            ),
            (
                serving_node_2_wallet,
                fully_specified_config.owed_to_serving_node_2.age_s,
            ),
            (
                serving_node_3_wallet,
                fully_specified_config.owed_to_serving_node_3.age_s,
            ),
        ]
        .iter()
        .for_each(|(wallet, age_s)| {
            let time_t = to_time_t(now.checked_sub(Duration::from_secs(*age_s)).unwrap());
            conn.prepare("update payable set last_paid_timestamp = ? where wallet_address = ?")
                .unwrap()
                .execute(&[&time_t as &dyn ToSql, &(wallet.to_string())])
                .unwrap();
        }),
    }

    let mut config_stmt = conn
        .prepare("update config set value = '0' where name = 'start_block'")
        .unwrap();
    config_stmt.execute([]).unwrap();
}

fn expire_receivables(path: PathBuf) {
    let conn = DbInitializerReal::default()
        .initialize(&path, DbInitializationConfig::panic_on_migration())
        .unwrap();
    let mut statement = conn
        .prepare("update receivable set last_received_timestamp = 0")
        .unwrap();
    statement.execute([]).unwrap();

    let mut config_stmt = conn
        .prepare("update config set value = '0' where name = 'start_block'")
        .unwrap();
    config_stmt.execute([]).unwrap();
}

struct TestInputsOutputsConfig {
    ui_ports_opt: Option<Ports>,
    // The contract owner wallet is populated with 100 ETH as defined in the set of commands
    // with which we start up the Ganache server.
    //
    // Specify number of wei this account should possess at its initialisation.
    // The consuming node gets the full balance of the contract owner if left as None.
    // Cannot ever get more than what the "owner" has.
    cons_node_initial_transaction_fee_balance_minor_opt: Option<u128>,
    cons_node_initial_service_fee_balance_minor: u128,
    debts_config: Either<SimpleSimulatedDebts, FullySpecifiedSimulatedDebts>,
    payment_thresholds_all_nodes: PaymentThresholds,
    cons_node_transaction_fee_agreed_unit_price_opt: Option<u64>,

    exp_final_cons_node_transaction_fee_balance_minor: u128,
    exp_final_cons_node_service_fee_balance_minor: u128,
    exp_final_service_fee_balance_serv_node_1_minor: u128,
    exp_final_service_fee_balance_serv_node_2_minor: u128,
    exp_final_service_fee_balance_serv_node_3_minor: u128,
}

enum NodeByRole {
    ConsNode,
    ServNode1,
    ServNode2,
    ServNode3,
}

struct SimpleSimulatedDebts {
    owed_to_serving_node_1_minor: u128,
    owed_to_serving_node_2_minor: u128,
    owed_to_serving_node_3_minor: u128,
}

struct FullySpecifiedSimulatedDebts {
    owed_to_serving_node_1: AccountedDebt,
    owed_to_serving_node_2: AccountedDebt,
    owed_to_serving_node_3: AccountedDebt,
}

struct AccountedDebt {
    balance_minor: u128,
    age_s: u64,
}

impl TestInputsOutputsConfig {
    fn port(&self, requested: NodeByRole) -> Option<u16> {
        self.ui_ports_opt.as_ref().map(|ports| match requested {
            NodeByRole::ConsNode => ports.consuming_node,
            NodeByRole::ServNode1 => ports.serving_node_1,
            NodeByRole::ServNode2 => ports.serving_node_2,
            NodeByRole::ServNode3 => ports.serving_node_3,
        })
    }

    fn debt_size(&self, requested: NodeByRole) -> u128 {
        match self.debts_config.as_ref() {
            Either::Left(simple_config) => match requested {
                NodeByRole::ServNode1 => simple_config.owed_to_serving_node_1_minor,
                NodeByRole::ServNode2 => simple_config.owed_to_serving_node_2_minor,
                NodeByRole::ServNode3 => simple_config.owed_to_serving_node_3_minor,
                NodeByRole::ConsNode => panic!(
                    "Version simple: These configs are \
                serve to set owed to the consuming node, while that one should not be here."
                ),
            },
            Either::Right(fully_specified) => match requested {
                NodeByRole::ServNode1 => fully_specified.owed_to_serving_node_1.balance_minor,
                NodeByRole::ServNode2 => fully_specified.owed_to_serving_node_2.balance_minor,
                NodeByRole::ServNode3 => fully_specified.owed_to_serving_node_3.balance_minor,
                NodeByRole::ConsNode => panic!(
                    "Version fully specified: These configs \
                are serve to set owed to the consuming node, while that one should not \
                be here."
                ),
            },
        }
    }
}

struct Ports {
    consuming_node: u16,
    serving_node_1: u16,
    serving_node_2: u16,
    serving_node_3: u16,
}

struct ServingNodeAttributes {
    name: String,
    index: usize,
    config: NodeStartupConfig,
}

fn test_body<StimulateConsumingNodePayments, StartServingNodesAndLetThemPerformReceivablesCheck>(
    global_config: TestInputsOutputsConfig,
    stimulate_consuming_node_to_pay: StimulateConsumingNodePayments,
    start_serving_nodes_and_run_check: StartServingNodesAndLetThemPerformReceivablesCheck,
) where
    StimulateConsumingNodePayments:
        FnOnce(&mut MASQNodeCluster, &MASQRealNode, &TestInputsOutputsConfig),
    StartServingNodesAndLetThemPerformReceivablesCheck:
        FnOnce(
            &mut MASQNodeCluster,
            ServingNodeAttributes,
            ServingNodeAttributes,
            ServingNodeAttributes,
            &TestInputsOutputsConfig,
        ) -> (MASQRealNode, MASQRealNode, MASQRealNode),
{
    let mut cluster = match MASQNodeCluster::start() {
        Ok(cluster) => cluster,
        Err(e) => panic!("{}", e),
    };
    let blockchain_server = BlockchainServer {
        name: "ganache-cli",
    };
    blockchain_server.start();
    blockchain_server.wait_until_ready();
    let url = blockchain_server.url().to_string();
    let (event_loop_handle, http) = Http::with_max_parallel(&url, REQUESTS_IN_PARALLEL).unwrap();
    let web3 = Web3::new(http.clone());
    let seed = make_seed();
    let (contract_owner_wallet, _) = make_node_wallet(&seed, &derivation_path(0, 0));
    let contract_addr = deploy_smart_contract(&contract_owner_wallet, &web3, cluster.chain);
    assert_eq!(
        contract_addr,
        cluster.chain.rec().contract,
        "Ganache is not as predictable as we thought: Update blockchain_interface::MULTINODE_CONTRACT_ADDRESS with {:?}",
        contract_addr
    );
    let blockchain_interface = BlockchainInterfaceWeb3::new(http, event_loop_handle, cluster.chain);
    let (consuming_config, consuming_node_wallet) = build_config(
        &blockchain_server,
        &seed,
        global_config.payment_thresholds_all_nodes,
        global_config.cons_node_transaction_fee_agreed_unit_price_opt,
        derivation_path(0, 1),
        global_config.port(NodeByRole::ConsNode),
    );
    eprintln!(
        "Consuming node wallet established: {}\n",
        consuming_node_wallet
    );
    let initial_transaction_fee_balance = global_config
        .cons_node_initial_transaction_fee_balance_minor_opt
        .unwrap_or(1_000_000_000_000_000_000);
    transfer_transaction_fee_amount_to_address(
        &contract_owner_wallet,
        &consuming_node_wallet,
        initial_transaction_fee_balance,
        1,
        &web3,
    );
    transfer_service_fee_amount_to_address(
        contract_addr,
        &contract_owner_wallet,
        &consuming_node_wallet,
        global_config.cons_node_initial_service_fee_balance_minor,
        2,
        &web3,
        cluster.chain,
    );
    assert_balances(
        &consuming_node_wallet,
        &blockchain_interface,
        global_config
            .cons_node_initial_transaction_fee_balance_minor_opt
            .unwrap_or(1_000_000_000_000_000_000),
        global_config.cons_node_initial_service_fee_balance_minor,
    );
    let (serving_node_1_config, serving_node_1_wallet) = build_config(
        &blockchain_server,
        &seed,
        global_config.payment_thresholds_all_nodes,
        None,
        derivation_path(0, 2),
        global_config.port(NodeByRole::ServNode1),
    );
    eprintln!(
        "First serving node wallet established: {}\n",
        serving_node_1_wallet
    );
    let (serving_node_2_config, serving_node_2_wallet) = build_config(
        &blockchain_server,
        &seed,
        global_config.payment_thresholds_all_nodes,
        None,
        derivation_path(0, 3),
        global_config.port(NodeByRole::ServNode2),
    );
    eprintln!(
        "Second serving node wallet established: {}\n",
        serving_node_2_wallet
    );
    let (serving_node_3_config, serving_node_3_wallet) = build_config(
        &blockchain_server,
        &seed,
        global_config.payment_thresholds_all_nodes,
        None,
        derivation_path(0, 4),
        global_config.port(NodeByRole::ServNode3),
    );
    eprintln!(
        "Third serving node wallet established: {}\n",
        serving_node_3_wallet
    );
    let (consuming_node_name, consuming_node_index) = cluster.prepare_real_node(&consuming_config);
    let consuming_node_path = node_chain_specific_data_directory(&consuming_node_name);
    let consuming_node_connection = DbInitializerReal::default()
        .initialize(
            Path::new(&consuming_node_path),
            make_init_config(cluster.chain),
        )
        .unwrap();
    let consuming_node_payable_dao = PayableDaoReal::new(consuming_node_connection);
    open_all_file_permissions(consuming_node_path.clone().into());
    assert_eq!(
        format!("{}", &consuming_node_wallet),
        "0x7a3cf474962646b18666b5a5be597bb0af013d81"
    );
    assert_eq!(
        format!("{}", &serving_node_1_wallet),
        "0x0bd8bc4b8aba5d8abf13ea78a6668ad0e9985ad6"
    );
    assert_eq!(
        format!("{}", &serving_node_2_wallet),
        "0xb329c8b029a2d3d217e71bc4d188e8e1a4a8b924"
    );
    assert_eq!(
        format!("{}", &serving_node_3_wallet),
        "0xb45a33ef3e3097f34c826369b74141ed268cdb5a"
    );
    let now = SystemTime::now();
    consuming_node_payable_dao
        .more_money_payable(
            now,
            &serving_node_1_wallet,
            global_config.debt_size(NodeByRole::ServNode1),
        )
        .unwrap();
    consuming_node_payable_dao
        .more_money_payable(
            now,
            &serving_node_2_wallet,
            global_config.debt_size(NodeByRole::ServNode2),
        )
        .unwrap();
    consuming_node_payable_dao
        .more_money_payable(
            now,
            &serving_node_3_wallet,
            global_config.debt_size(NodeByRole::ServNode3),
        )
        .unwrap();
    let (serving_node_1_name, serving_node_1_index) =
        cluster.prepare_real_node(&serving_node_1_config);
    let serving_node_1_path = node_chain_specific_data_directory(&serving_node_1_name);
    let serving_node_1_connection = DbInitializerReal::default()
        .initialize(
            Path::new(&serving_node_1_path),
            make_init_config(cluster.chain),
        )
        .unwrap();
    let serving_node_1_receivable_dao = ReceivableDaoReal::new(serving_node_1_connection);
    serving_node_1_receivable_dao
        .more_money_receivable(
            SystemTime::now(),
            &consuming_node_wallet,
            global_config.debt_size(NodeByRole::ServNode1),
        )
        .unwrap();
    open_all_file_permissions(serving_node_1_path.clone().into());
    let (serving_node_2_name, serving_node_2_index) =
        cluster.prepare_real_node(&serving_node_2_config);
    let serving_node_2_path = node_chain_specific_data_directory(&serving_node_2_name);
    let serving_node_2_connection = DbInitializerReal::default()
        .initialize(
            Path::new(&serving_node_2_path),
            make_init_config(cluster.chain),
        )
        .unwrap();
    let serving_node_2_receivable_dao = ReceivableDaoReal::new(serving_node_2_connection);
    serving_node_2_receivable_dao
        .more_money_receivable(
            SystemTime::now(),
            &consuming_node_wallet,
            global_config.debt_size(NodeByRole::ServNode2),
        )
        .unwrap();
    open_all_file_permissions(serving_node_2_path.clone().into());
    let (serving_node_3_name, serving_node_3_index) =
        cluster.prepare_real_node(&serving_node_3_config);
    let serving_node_3_path = node_chain_specific_data_directory(&serving_node_3_name);
    let serving_node_3_connection = DbInitializerReal::default()
        .initialize(
            Path::new(&serving_node_3_path),
            make_init_config(cluster.chain),
        )
        .unwrap();
    let serving_node_3_receivable_dao = ReceivableDaoReal::new(serving_node_3_connection);
    serving_node_3_receivable_dao
        .more_money_receivable(
            SystemTime::now(),
            &consuming_node_wallet,
            global_config.debt_size(NodeByRole::ServNode3),
        )
        .unwrap();
    open_all_file_permissions(serving_node_3_path.clone().into());
    expire_payables(
        consuming_node_path.into(),
        &global_config.debts_config,
        now,
        &serving_node_1_wallet,
        &serving_node_2_wallet,
        &serving_node_3_wallet,
    );
    expire_receivables(serving_node_1_path.into());
    expire_receivables(serving_node_2_path.into());
    expire_receivables(serving_node_3_path.into());
    assert_balances(&serving_node_1_wallet, &blockchain_interface, 0, 0);
    assert_balances(&serving_node_2_wallet, &blockchain_interface, 0, 0);
    assert_balances(&serving_node_3_wallet, &blockchain_interface, 0, 0);
    let real_consuming_node =
        cluster.start_named_real_node(&consuming_node_name, consuming_node_index, consuming_config);

    stimulate_consuming_node_to_pay(&mut cluster, &real_consuming_node, &global_config);

    let now = Instant::now();
    while !consuming_node_payable_dao.non_pending_payables().is_empty()
        && now.elapsed() < Duration::from_secs(10)
    {
        thread::sleep(Duration::from_millis(400));
    }
    assert_balances(
        &consuming_node_wallet,
        &blockchain_interface,
        global_config.exp_final_cons_node_transaction_fee_balance_minor,
        global_config.exp_final_cons_node_service_fee_balance_minor,
    );
    assert_balances(
        &serving_node_1_wallet,
        &blockchain_interface,
        0,
        global_config.exp_final_service_fee_balance_serv_node_1_minor,
    );
    assert_balances(
        &serving_node_2_wallet,
        &blockchain_interface,
        0,
        global_config.exp_final_service_fee_balance_serv_node_2_minor,
    );
    assert_balances(
        &serving_node_3_wallet,
        &blockchain_interface,
        0,
        global_config.exp_final_service_fee_balance_serv_node_3_minor,
    );
    let serving_node_1_attributes = ServingNodeAttributes {
        name: serving_node_1_name.to_string(),
        index: serving_node_1_index,
        config: serving_node_1_config,
    };
    let serving_node_2_attributes = ServingNodeAttributes {
        name: serving_node_2_name.to_string(),
        index: serving_node_2_index,
        config: serving_node_2_config,
    };
    let serving_node_3_attributes = ServingNodeAttributes {
        name: serving_node_3_name.to_string(),
        index: serving_node_3_index,
        config: serving_node_3_config,
    };
    start_serving_nodes_and_run_check(
        &mut cluster,
        serving_node_1_attributes,
        serving_node_2_attributes,
        serving_node_3_attributes,
        &global_config,
    );
    test_utils::wait_for(Some(1000), Some(15000), || {
        if let Some(status) = serving_node_1_receivable_dao.account_status(&consuming_node_wallet) {
            status.balance_wei
                == i128::try_from(
                    global_config.debt_size(NodeByRole::ServNode1)
                        - global_config.exp_final_service_fee_balance_serv_node_1_minor,
                )
                .unwrap()
        } else {
            false
        }
    });
    test_utils::wait_for(Some(1000), Some(15000), || {
        if let Some(status) = serving_node_2_receivable_dao.account_status(&consuming_node_wallet) {
            status.balance_wei
                == i128::try_from(
                    global_config.debt_size(NodeByRole::ServNode2)
                        - global_config.exp_final_service_fee_balance_serv_node_2_minor,
                )
                .unwrap()
        } else {
            false
        }
    });
    test_utils::wait_for(Some(1000), Some(15000), || {
        if let Some(status) = serving_node_3_receivable_dao.account_status(&consuming_node_wallet) {
            status.balance_wei
                == i128::try_from(
                    global_config.debt_size(NodeByRole::ServNode3)
                        - global_config.exp_final_service_fee_balance_serv_node_3_minor,
                )
                .unwrap()
        } else {
            false
        }
    });
}
