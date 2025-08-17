// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Display;

pub mod app_rpc_web3_error;

pub trait BlockchainError: Display {}
