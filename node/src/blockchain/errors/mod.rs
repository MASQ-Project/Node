// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//! Error handling hierarchy for blockchain operations.
//!
//! This module provides a two-tier error system:
//! 
//! ## BlockchainDbError
//! Compact, serializable errors suitable for database storage. These errors
//! contain only essential information and are designed to be space-efficient.
//!
//! ## BlockchainLoggableError  
//! Verbose errors with full context for logging and debugging. These errors
//! contain detailed information but are not suitable for database storage.
//!
//! ## Conversion
//! `BlockchainLoggableError` can be downgraded to `BlockchainDbError` for storage,
//! trading detail for space efficiency.

pub mod blockchain_db_error;
pub mod blockchain_loggable_error;
mod common_methods;
mod test_utils;
pub mod validation_status;
