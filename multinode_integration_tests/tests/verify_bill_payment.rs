// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::verify_bill_payment_utils::utils::{
    test_body, to_wei, AssertionsValues, Debt, DebtsSpecs, FinalServiceFeeBalancesByServingNodes,
    GlobalValues, NodeByRole, Ports, ServingNodeAttributes, TestInputsBuilder,
};
use masq_lib::blockchains::chains::Chain;
use masq_lib::messages::FromMessageBody;
use masq_lib::messages::ToMessageBody;
use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
use masq_lib::percentage::PurePercentage;
use masq_lib::utils::{find_free_port};
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{MASQRealNode,
    NodeStartupConfigBuilder,
};
use node_lib::accountant::gwei_to_wei;
use node_lib::sub_lib::accountant::PaymentThresholds;
use node_lib::sub_lib::blockchain_interface_web3::{
    compute_gas_limit, web3_gas_limit_const_part,
};
use std::convert::TryFrom;
use std::time::{Duration, UNIX_EPOCH};
use std::{u128};
mod verify_bill_payment_utils;

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
    let test_inputs = TestInputsBuilder::default()
        .consuming_node_initial_service_fee_balance_minor(
            consuming_node_initial_service_fee_balance_minor,
        )
        .debts_config(DebtsSpecs::new(
            Debt::new(owed_to_serving_node_1_minor, long_ago),
            Debt::new(owed_to_serving_node_2_minor, long_ago),
            Debt::new(owed_to_serving_node_3_minor, long_ago),
        ))
        .payment_thresholds_all_nodes(payment_thresholds)
        .build();
    let debts_total =
        owed_to_serving_node_1_minor + owed_to_serving_node_2_minor + owed_to_serving_node_3_minor;
    let final_consuming_node_service_fee_balance_minor =
        consuming_node_initial_service_fee_balance_minor - debts_total;
    let assertions_values = AssertionsValues {
        final_consuming_node_transaction_fee_balance_minor: to_wei(999_842_470),
        final_consuming_node_service_fee_balance_minor,
        final_service_fee_balances_by_serving_nodes: FinalServiceFeeBalancesByServingNodes::new(
            owed_to_serving_node_1_minor,
            owed_to_serving_node_2_minor,
            owed_to_serving_node_3_minor,
        ),
    };

    test_body(
        test_inputs,
        assertions_values,
        stimulate_consuming_node_to_pay_for_test_with_sufficient_funds,
        activating_serving_nodes_for_test_with_sufficient_funds,
    );
}

fn stimulate_consuming_node_to_pay_for_test_with_sufficient_funds(
    cluster: &mut MASQNodeCluster,
    real_consuming_node: &MASQRealNode,
    _global_values: &GlobalValues,
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

fn activating_serving_nodes_for_test_with_sufficient_funds(
    cluster: &mut MASQNodeCluster,
    serving_nodes: &mut [ServingNodeAttributes; 3],
    _global_values: &GlobalValues,
) -> [MASQRealNode; 3] {
    let (node_references, serving_nodes): (Vec<_>, Vec<_>) = serving_nodes
        .into_iter()
        .map(|attributes| {
            let namings = &attributes.common.node_id;
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
        enough_balance_for_serving_node_1_and_2 - to_wei(2_345_678);
    let gas_price_major = 60;
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
        transaction_fee_margin.add_percent_to(gas_limit_dev_chain * gas_price_major)
    };
    const AFFORDABLE_PAYMENTS_COUNT: u128 = 2;
    let tx_fee_needed_to_pay_for_one_payment_minor: u128 =
        gwei_to_wei(tx_fee_needed_to_pay_for_one_payment_major);
    let consuming_node_transaction_fee_balance_minor =
        AFFORDABLE_PAYMENTS_COUNT * tx_fee_needed_to_pay_for_one_payment_minor;
    let test_inputs = TestInputsBuilder::default()
        .ui_ports(Ports::new(
            find_free_port(),
            find_free_port(),
            find_free_port(),
            find_free_port(),
        ))
        // Should be enough only for two payments, the least significant one will fall out
        .consuming_node_initial_tx_fee_balance_minor(consuming_node_transaction_fee_balance_minor)
        .consuming_node_initial_service_fee_balance_minor(
            consuming_node_initial_service_fee_balance_minor,
        )
        .debts_config(DebtsSpecs::new(
            // This account will be the most significant and will deserve the full balance
            Debt::new(
                owed_to_serv_node_1_minor,
                payment_thresholds.maturity_threshold_sec + 1000,
            ),
            // This balance is of a middle size it will be reduced as there won't be enough
            // after the first one is filled up.
            Debt::new(
                owed_to_serv_node_2_minor,
                payment_thresholds.maturity_threshold_sec + 100_000,
            ),
            // This account will be the least significant, therefore eliminated due to tx fee
            Debt::new(
                owed_to_serv_node_3_minor,
                payment_thresholds.maturity_threshold_sec + 30_000,
            ),
        ))
        .payment_thresholds_all_nodes(payment_thresholds)
        .consuming_node_gas_price_major(gas_price_major)
        .build();

    let assertions_values = AssertionsValues {
        // How much is left after the smart contract was successfully executed, those three payments
        final_consuming_node_transaction_fee_balance_minor: to_wei(2_828_352),
        // Zero reached, because the algorithm is designed to exhaust the wallet completely
        final_consuming_node_service_fee_balance_minor: 0,
        // This account was granted with the full size as its lowest balance from the set makes
        // it weight the most
        final_service_fee_balances_by_serving_nodes: FinalServiceFeeBalancesByServingNodes::new(
            owed_to_serv_node_1_minor,
            owed_to_serv_node_2_minor - to_wei(2_345_678),
            // This account dropped out from the payment, so received no money
            0,
        ),
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
                &common.node_id.node_name,
                common.node_id.index,
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