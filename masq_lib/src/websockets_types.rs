// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use futures_util::io::{BufReader, BufWriter};
use soketto::{Receiver, Sender};
use tokio::net::TcpStream;
use tokio_util::compat::Compat;

pub type WSSender = Sender<BufReader<BufWriter<Compat<TcpStream>>>>;
pub type WSReceiver = Receiver<BufReader<BufWriter<Compat<TcpStream>>>>;
