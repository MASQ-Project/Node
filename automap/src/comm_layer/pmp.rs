// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use crate::comm_layer::PmpTransaction;

pub struct GetPublicIp {

}

impl PmpTransaction for GetPublicIp {}

pub struct AddMapping {

}

impl PmpTransaction for AddMapping {}

pub struct DeleteMapping {

}

impl PmpTransaction for DeleteMapping {}
