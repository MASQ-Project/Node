// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use web3::Transport;
use std::fmt::Debug;

pub trait Web3Wrapper{

}

pub struct Web3WrapperReal<T: Transport + Debug>{
    web3: We3<T>
}