// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use masq_lib::utils::AutomapProtocol;
use masq_lib::utils::NeighborhoodModeLight;
use std::any::Any;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[allow(clippy::type_complexity)]
#[derive(Clone, Default)]
pub struct PersistentConfigurationMock {
    blockchain_service_url_results: RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    set_blockchain_service_url_params: Arc<Mutex<Vec<String>>>,
    set_blockchain_service_url_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    current_schema_version_results: RefCell<Vec<String>>,
    chain_name_params: Arc<Mutex<Vec<()>>>,
    chain_name_results: RefCell<Vec<String>>,
    check_password_params: Arc<Mutex<Vec<Option<String>>>>,
    check_password_results: RefCell<Vec<Result<bool, PersistentConfigError>>>,
    change_password_params: Arc<Mutex<Vec<(Option<String>, String)>>>,
    change_password_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    clandestine_port_results: RefCell<Vec<Result<u16, PersistentConfigError>>>,
    set_clandestine_port_params: Arc<Mutex<Vec<u16>>>,
    set_clandestine_port_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    gas_price_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_gas_price_params: Arc<Mutex<Vec<u64>>>,
    set_gas_price_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    consuming_wallet_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_results: RefCell<Vec<Result<Option<Wallet>, PersistentConfigError>>>,
    consuming_wallet_private_key_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_private_key_results:
        RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    earning_wallet_results: RefCell<Vec<Result<Option<Wallet>, PersistentConfigError>>>,
    earning_wallet_address_results: RefCell<Vec<Result<Option<String>, PersistentConfigError>>>,
    set_wallet_info_params: Arc<Mutex<Vec<(String, String, String)>>>,
    set_wallet_info_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    mapping_protocol_results: RefCell<Vec<Result<Option<AutomapProtocol>, PersistentConfigError>>>,
    set_mapping_protocol_params: Arc<Mutex<Vec<Option<AutomapProtocol>>>>,
    set_mapping_protocol_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    neighborhood_mode_results: RefCell<Vec<Result<NeighborhoodModeLight, PersistentConfigError>>>,
    set_neighborhood_mode_params: Arc<Mutex<Vec<NeighborhoodModeLight>>>,
    set_neighborhood_mode_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    past_neighbors_params: Arc<Mutex<Vec<String>>>,
    past_neighbors_results:
        RefCell<Vec<Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>>>,
    set_past_neighbors_params: Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    set_past_neighbors_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    start_block_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_start_block_params: Arc<Mutex<Vec<u64>>>,
    set_start_block_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    balance_decreases_for_sec_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_balance_decreases_for_sec_params: Arc<Mutex<Vec<u64>>>,
    set_balance_decreases_for_sec_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    balance_to_decrease_from_gwei_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_balance_to_decrease_from_gwei_params: Arc<Mutex<Vec<u64>>>,
    set_balance_to_decrease_from_gwei_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    exit_byte_rate_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_exit_byte_rate_params: Arc<Mutex<Vec<u64>>>,
    set_exit_byte_rate_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    exit_service_rate_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_exit_service_rate_params: Arc<Mutex<Vec<u64>>>,
    set_exit_service_rate_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    payable_scan_interval_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_payable_scan_interval_params: Arc<Mutex<Vec<u64>>>,
    set_payable_scan_interval_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    payment_suggested_after_sec_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_payment_suggested_after_sec_params: Arc<Mutex<Vec<u64>>>,
    set_payment_suggested_after_sec_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    payment_grace_before_ban_sec_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_payment_grace_before_ban_sec_params: Arc<Mutex<Vec<u64>>>,
    set_payment_grace_before_ban_sec_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    pending_payment_scan_interval_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_pending_payment_scan_interval_params: Arc<Mutex<Vec<u64>>>,
    set_pending_payment_scan_interval_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    permanent_debt_allowed_gwei_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_permanent_debt_allowed_gwei_params: Arc<Mutex<Vec<u64>>>,
    set_permanent_debt_allowed_gwei_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    receivable_scan_interval_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_receivable_scan_interval_params: Arc<Mutex<Vec<u64>>>,
    set_receivable_scan_interval_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    routing_byte_rate_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_routing_byte_rate_params: Arc<Mutex<Vec<u64>>>,
    set_routing_byte_rate_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    routing_services_rate_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_routing_service_rate_params: Arc<Mutex<Vec<u64>>>,
    set_routing_service_rate_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    unban_when_balance_below_gwei_results: RefCell<Vec<Result<u64, PersistentConfigError>>>,
    set_unban_when_balance_below_gwei_params: Arc<Mutex<Vec<u64>>>,
    set_unban_when_balance_below_gwei_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
}

impl PersistentConfiguration for PersistentConfigurationMock {
    fn balance_decreases_for_sec(&self) -> Result<u64, PersistentConfigError> {
        self.balance_decreases_for_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn set_balance_decreases_for_sec(
        &mut self,
        interval: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_balance_decreases_for_sec_params
            .lock()
            .unwrap()
            .push(interval);
        self.set_balance_decreases_for_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn balance_to_decrease_from_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.balance_to_decrease_from_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn set_balance_to_decrease_from_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_balance_to_decrease_from_gwei_params
            .lock()
            .unwrap()
            .push(level);
        self.set_balance_to_decrease_from_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn blockchain_service_url(&self) -> Result<Option<String>, PersistentConfigError> {
        self.blockchain_service_url_results.borrow_mut().remove(0)
    }

    fn set_blockchain_service_url(&mut self, url: &str) -> Result<(), PersistentConfigError> {
        self.set_blockchain_service_url_params
            .lock()
            .unwrap()
            .push(url.to_string());
        self.set_blockchain_service_url_results
            .borrow_mut()
            .remove(0)
    }

    fn current_schema_version(&self) -> String {
        Self::result_from(&self.current_schema_version_results)
    }

    fn chain_name(&self) -> String {
        self.chain_name_params.lock().unwrap().push(());
        self.chain_name_results.borrow_mut().remove(0)
    }

    fn check_password(
        &self,
        db_password_opt: Option<String>,
    ) -> Result<bool, PersistentConfigError> {
        self.check_password_params
            .lock()
            .unwrap()
            .push(db_password_opt);
        self.check_password_results.borrow_mut().remove(0)
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<String>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.change_password_params
            .lock()
            .unwrap()
            .push((old_password_opt, db_password.to_string()));
        self.change_password_results.borrow_mut().remove(0)
    }

    fn consuming_wallet(&self, db_password: &str) -> Result<Option<Wallet>, PersistentConfigError> {
        self.consuming_wallet_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        Self::result_from(&self.consuming_wallet_results)
    }

    fn consuming_wallet_private_key(
        &self,
        db_password: &str,
    ) -> Result<Option<String>, PersistentConfigError> {
        self.consuming_wallet_private_key_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        Self::result_from(&self.consuming_wallet_private_key_results)
    }

    fn clandestine_port(&self) -> Result<u16, PersistentConfigError> {
        Self::result_from(&self.clandestine_port_results)
    }

    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError> {
        self.set_clandestine_port_params.lock().unwrap().push(port);
        self.set_clandestine_port_results.borrow_mut().remove(0)
    }

    fn earning_wallet(&self) -> Result<Option<Wallet>, PersistentConfigError> {
        Self::result_from(&self.earning_wallet_results)
    }

    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError> {
        Self::result_from(&self.earning_wallet_address_results)
    }

    fn exit_byte_rate(&self) -> Result<u64, PersistentConfigError> {
        self.exit_byte_rate_results.borrow_mut().remove(0)
    }

    fn set_exit_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.set_exit_byte_rate_params.lock().unwrap().push(rate);
        self.set_exit_byte_rate_results.borrow_mut().remove(0)
    }

    fn exit_service_rate(&self) -> Result<u64, PersistentConfigError> {
        self.exit_service_rate_results.borrow_mut().remove(0)
    }

    fn set_exit_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.set_exit_service_rate_params.lock().unwrap().push(rate);
        self.set_exit_service_rate_results.borrow_mut().remove(0)
    }

    fn gas_price(&self) -> Result<u64, PersistentConfigError> {
        Self::result_from(&self.gas_price_results)
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        self.set_gas_price_params.lock().unwrap().push(gas_price);
        self.set_gas_price_results.borrow_mut().remove(0)
    }

    fn mapping_protocol(&self) -> Result<Option<AutomapProtocol>, PersistentConfigError> {
        self.mapping_protocol_results.borrow_mut().remove(0)
    }

    fn set_mapping_protocol(
        &mut self,
        value: Option<AutomapProtocol>,
    ) -> Result<(), PersistentConfigError> {
        self.set_mapping_protocol_params.lock().unwrap().push(value);
        self.set_mapping_protocol_results.borrow_mut().remove(0)
    }

    fn neighborhood_mode(&self) -> Result<NeighborhoodModeLight, PersistentConfigError> {
        self.neighborhood_mode_results.borrow_mut().remove(0)
    }

    fn set_neighborhood_mode(
        &mut self,
        value: NeighborhoodModeLight,
    ) -> Result<(), PersistentConfigError> {
        self.set_neighborhood_mode_params
            .lock()
            .unwrap()
            .push(value);
        self.set_neighborhood_mode_results.borrow_mut().remove(0)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        self.past_neighbors_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        self.past_neighbors_results.borrow_mut().remove(0)
    }

    fn set_past_neighbors(
        &mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_past_neighbors_params
            .lock()
            .unwrap()
            .push((node_descriptors_opt, db_password.to_string()));
        self.set_past_neighbors_results.borrow_mut().remove(0)
    }

    fn payable_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.payable_scan_interval_results.borrow_mut().remove(0)
    }

    fn set_payable_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_payable_scan_interval_params
            .lock()
            .unwrap()
            .push(interval_sec);
        self.set_payable_scan_interval_results
            .borrow_mut()
            .remove(0)
    }

    fn payment_grace_before_ban_sec(&self) -> Result<u64, PersistentConfigError> {
        self.payment_grace_before_ban_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn set_payment_grace_before_ban_sec(
        &mut self,
        period_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_payment_grace_before_ban_sec_params
            .lock()
            .unwrap()
            .push(period_sec);
        self.set_payment_grace_before_ban_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn payment_suggested_after_sec(&self) -> Result<u64, PersistentConfigError> {
        self.payment_suggested_after_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn set_payment_suggested_after_sec(
        &mut self,
        period: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_payment_suggested_after_sec_params
            .lock()
            .unwrap()
            .push(period);
        self.set_payment_suggested_after_sec_results
            .borrow_mut()
            .remove(0)
    }

    fn pending_payment_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.pending_payment_scan_interval_results
            .borrow_mut()
            .remove(0)
    }

    fn set_pending_payment_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_pending_payment_scan_interval_params
            .lock()
            .unwrap()
            .push(interval_sec);
        self.set_pending_payment_scan_interval_results
            .borrow_mut()
            .remove(0)
    }

    fn permanent_debt_allowed_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.permanent_debt_allowed_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn set_permanent_debt_allowed_gwei(
        &mut self,
        debt_amount: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_permanent_debt_allowed_gwei_params
            .lock()
            .unwrap()
            .push(debt_amount);
        self.set_permanent_debt_allowed_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn receivable_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.receivable_scan_interval_results.borrow_mut().remove(0)
    }

    fn set_receivable_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_receivable_scan_interval_params
            .lock()
            .unwrap()
            .push(interval_sec);
        self.set_receivable_scan_interval_results
            .borrow_mut()
            .remove(0)
    }

    fn routing_byte_rate(&self) -> Result<u64, PersistentConfigError> {
        self.routing_byte_rate_results.borrow_mut().remove(0)
    }

    fn set_routing_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.set_routing_byte_rate_params.lock().unwrap().push(rate);
        self.set_routing_byte_rate_results.borrow_mut().remove(0)
    }

    fn routing_service_rate(&self) -> Result<u64, PersistentConfigError> {
        self.routing_services_rate_results.borrow_mut().remove(0)
    }

    fn set_routing_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.set_routing_service_rate_params
            .lock()
            .unwrap()
            .push(rate);
        self.set_routing_service_rate_results.borrow_mut().remove(0)
    }

    fn start_block(&self) -> Result<u64, PersistentConfigError> {
        if self.start_block_results.borrow().is_empty() {
            return Ok(0);
        }
        Self::result_from(&self.start_block_results)
    }

    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError> {
        self.set_start_block_params.lock().unwrap().push(value);
        Self::result_from(&self.set_start_block_results)
    }

    fn unban_when_balance_below_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.unban_when_balance_below_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn set_unban_when_balance_below_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError> {
        self.set_unban_when_balance_below_gwei_params
            .lock()
            .unwrap()
            .push(level);
        self.set_unban_when_balance_below_gwei_results
            .borrow_mut()
            .remove(0)
    }

    fn set_wallet_info(
        &mut self,
        consuming_wallet_private_key: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_wallet_info_params.lock().unwrap().push((
            consuming_wallet_private_key.to_string(),
            earning_wallet_address.to_string(),
            db_password.to_string(),
        ));
        self.set_wallet_info_results.borrow_mut().remove(0)
    }

    as_any_impl!();
}

impl PersistentConfigurationMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn blockchain_service_url_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> Self {
        self.blockchain_service_url_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_blockchain_service_url_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_blockchain_service_url_params = params.clone();
        self
    }

    pub fn set_blockchain_service_url_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_blockchain_service_url_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn current_schema_version_result(self, result: &str) -> PersistentConfigurationMock {
        self.current_schema_version_results
            .borrow_mut()
            .push(result.to_string());
        self
    }

    pub fn chain_name_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.chain_name_params = params.clone();
        self
    }

    pub fn chain_name_result(self, result: String) -> Self {
        self.chain_name_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn change_password_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<String>, String)>>>,
    ) -> PersistentConfigurationMock {
        self.change_password_params = params.clone();
        self
    }

    pub fn change_password_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.change_password_results.borrow_mut().push(result);
        self
    }

    pub fn check_password_params(
        mut self,
        params: &Arc<Mutex<Vec<Option<String>>>>,
    ) -> PersistentConfigurationMock {
        self.check_password_params = params.clone();
        self
    }

    pub fn check_password_result(
        self,
        result: Result<bool, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.check_password_results.borrow_mut().push(result);
        self
    }

    pub fn clandestine_port_result(
        self,
        result: Result<u16, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.clandestine_port_results.borrow_mut().push(result);
        self
    }

    pub fn set_clandestine_port_params(
        mut self,
        params: &Arc<Mutex<Vec<u16>>>,
    ) -> PersistentConfigurationMock {
        self.set_clandestine_port_params = params.clone();
        self
    }

    pub fn set_clandestine_port_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_clandestine_port_results.borrow_mut().push(result);
        self
    }

    pub fn neighborhood_mode_result(
        self,
        result: Result<NeighborhoodModeLight, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.neighborhood_mode_results.borrow_mut().push(result);
        self
    }

    pub fn set_neighborhood_mode_params(
        mut self,
        params: &Arc<Mutex<Vec<NeighborhoodModeLight>>>,
    ) -> PersistentConfigurationMock {
        self.set_neighborhood_mode_params = params.clone();
        self
    }

    pub fn set_neighborhood_mode_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_neighborhood_mode_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_params = params.clone();
        self
    }

    pub fn consuming_wallet_result(
        self,
        result: Result<Option<Wallet>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_private_key_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_private_key_params = params.clone();
        self
    }

    pub fn consuming_wallet_private_key_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_private_key_results
            .borrow_mut()
            .push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_wallet_info_params(
        mut self,
        params: &Arc<Mutex<Vec<(String, String, String)>>>,
    ) -> PersistentConfigurationMock {
        self.set_wallet_info_params = params.clone();
        self
    }

    pub fn set_wallet_info_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_wallet_info_results.borrow_mut().push(result);
        self
    }

    pub fn gas_price_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn set_gas_price_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> PersistentConfigurationMock {
        self.set_gas_price_params = params.clone();
        self
    }

    pub fn set_gas_price_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn past_neighbors_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.past_neighbors_params = params.clone();
        self
    }

    pub fn past_neighbors_result(
        self,
        result: Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.past_neighbors_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_past_neighbors_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    ) -> PersistentConfigurationMock {
        self.set_past_neighbors_params = params.clone();
        self
    }

    pub fn set_past_neighbors_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_past_neighbors_results.borrow_mut().push(result);
        self
    }

    pub fn earning_wallet_result(
        self,
        result: Result<Option<Wallet>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_results.borrow_mut().push(result);
        self
    }

    pub fn earning_wallet_address_result(
        self,
        result: Result<Option<String>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_address_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn start_block_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.start_block_results.borrow_mut().push(result);
        self
    }

    pub fn set_start_block_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> PersistentConfigurationMock {
        self.set_start_block_params = params.clone();
        self
    }

    pub fn set_start_block_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_start_block_results.borrow_mut().push(result);
        self
    }

    pub fn balance_decreases_for_sec_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.balance_decreases_for_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_balance_decreases_for_sec_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_balance_decreases_for_sec_params = params.clone();
        self
    }

    pub fn set_balance_decreases_for_sec_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_balance_decreases_for_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn balance_to_decrease_from_gwei_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.balance_to_decrease_from_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_balance_to_decrease_from_gwei_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> Self {
        self.set_balance_to_decrease_from_gwei_params = params.clone();
        self
    }

    pub fn set_balance_to_decrease_from_gwei_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_balance_to_decrease_from_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn exit_byte_rate_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.exit_byte_rate_results.borrow_mut().push(result);
        self
    }

    pub fn set_exit_byte_rate_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_exit_byte_rate_params = params.clone();
        self
    }

    pub fn set_exit_byte_rate_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_exit_byte_rate_results.borrow_mut().push(result);
        self
    }

    pub fn exit_service_rate_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.exit_service_rate_results.borrow_mut().push(result);
        self
    }

    pub fn set_exit_service_rate_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_exit_service_rate_params = params.clone();
        self
    }

    pub fn set_exit_service_rate_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_exit_service_rate_results.borrow_mut().push(result);
        self
    }

    pub fn payable_scan_interval_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.payable_scan_interval_results.borrow_mut().push(result);
        self
    }

    pub fn set_payable_scan_interval_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_payable_scan_interval_params = params.clone();
        self
    }

    pub fn set_payable_scan_interval_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_payable_scan_interval_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn payment_suggested_after_sec_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.payment_suggested_after_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_payment_suggested_after_sec_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_payment_suggested_after_sec_params = params.clone();
        self
    }

    pub fn set_payment_suggested_after_sec_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_payment_suggested_after_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn payment_grace_before_ban_sec_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.payment_grace_before_ban_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_payment_grace_before_ban_sec_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> Self {
        self.set_payment_grace_before_ban_sec_params = params.clone();
        self
    }

    pub fn set_payment_grace_before_ban_sec_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_payment_grace_before_ban_sec_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn pending_payment_scan_interval_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.pending_payment_scan_interval_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_pending_payment_scan_interval_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> Self {
        self.set_pending_payment_scan_interval_params = params.clone();
        self
    }

    pub fn set_pending_payment_scan_interval_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_pending_payment_scan_interval_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn permanent_debt_allowed_gwei_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.permanent_debt_allowed_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_permanent_debt_allowed_gwei_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_permanent_debt_allowed_gwei_params = params.clone();
        self
    }

    pub fn set_permanent_debt_allowed_gwei_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_permanent_debt_allowed_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn receivable_scan_interval_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.receivable_scan_interval_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_receivable_scan_interval_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_receivable_scan_interval_params = params.clone();
        self
    }

    pub fn set_receivable_scan_interval_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_receivable_scan_interval_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn routing_byte_rate_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.routing_byte_rate_results.borrow_mut().push(result);
        self
    }

    pub fn set_routing_byte_rate_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_routing_byte_rate_params = params.clone();
        self
    }

    pub fn set_routing_byte_rate_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_routing_byte_rate_results.borrow_mut().push(result);
        self
    }

    pub fn routing_service_rate_result(self, result: Result<u64, PersistentConfigError>) -> Self {
        self.routing_services_rate_results.borrow_mut().push(result);
        self
    }

    pub fn set_routing_service_rate_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.set_routing_service_rate_params = params.clone();
        self
    }

    pub fn set_routing_service_rate_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_routing_service_rate_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn unban_when_balance_below_gwei_result(
        self,
        result: Result<u64, PersistentConfigError>,
    ) -> Self {
        self.unban_when_balance_below_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_unban_when_balance_below_gwei_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> Self {
        self.set_unban_when_balance_below_gwei_params = params.clone();
        self
    }

    pub fn set_unban_when_balance_below_gwei_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> Self {
        self.set_unban_when_balance_below_gwei_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn mapping_protocol_result(
        self,
        result: Result<Option<AutomapProtocol>, PersistentConfigError>,
    ) -> Self {
        self.mapping_protocol_results.borrow_mut().push(result);
        self
    }

    pub fn set_mapping_protocol_params(
        mut self,
        params: &Arc<Mutex<Vec<Option<AutomapProtocol>>>>,
    ) -> Self {
        self.set_mapping_protocol_params = params.clone();
        self
    }

    pub fn set_mapping_protocol_result(self, result: Result<(), PersistentConfigError>) -> Self {
        self.set_mapping_protocol_results.borrow_mut().push(result);
        self
    }

    fn result_from<T: Clone>(results: &RefCell<Vec<T>>) -> T {
        let mut borrowed = results.borrow_mut();
        if borrowed.is_empty() {
            panic!("No mock results prepared")
        } else if borrowed.len() == 1 {
            borrowed[0].clone()
        } else {
            borrowed.remove(0)
        }
    }
}
