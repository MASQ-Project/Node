use crate::gossip_builder::GossipBuilder;
use crate::substratum_client::SubstratumNodeClient;
use crate::substratum_mock_node::SubstratumMockNode;
use crate::substratum_node::NodeReference;
use crate::substratum_node::PortSelector;
use crate::substratum_node::SubstratumNode;
use crate::substratum_node::SubstratumNodeUtils;
use neighborhood_lib::gossip::GossipNodeRecord;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use neighborhood_lib::neighborhood_database::NodeSignatures;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::masquerader::Masquerader;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::PublicKey;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::wallet::Wallet;
use sub_lib::cryptde_null::CryptDENull;

#[derive(Clone)]
pub struct MockBootstrapNode {
    name: String,
    node_reference: NodeReference,
    nodes_arc: Arc<Mutex<Vec<GossipNodeRecord>>>,
}

impl SubstratumNode for MockBootstrapNode {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn node_reference(&self) -> NodeReference {
        self.node_reference.clone()
    }

    fn public_key(&self) -> PublicKey {
        self.node_reference.public_key.clone()
    }

    fn cryptde(&self) -> CryptDENull {CryptDENull::from (&self.public_key())}

    fn ip_address(&self) -> IpAddr {
        self.node_reference.node_addr.ip_addr()
    }

    fn port_list(&self) -> Vec<u16> {
        self.node_reference.node_addr.ports()
    }

    fn node_addr(&self) -> NodeAddr {
        self.node_reference.node_addr.clone()
    }

    fn socket_addr(&self, port_selector: PortSelector) -> SocketAddr {
        SubstratumNodeUtils::socket_addr(&self.node_addr(), port_selector, self.name())
    }

    fn earning_wallet(&self) -> Wallet {
        panic!("Bootstrap nodes (even mock ones) can't have earning wallets")
    }

    fn consuming_wallet(&self) -> Option<Wallet> {
        panic!("Bootstrap nodes (even mock ones) can't have consuming wallets")
    }

    fn make_client(&self, _port: u16) -> SubstratumNodeClient {
        panic!("Bootstrap nodes (even mock ones) can't have clients")
    }
}

impl MockBootstrapNode {
    pub fn start(
        ports: Vec<u16>,
        index: usize,
        host_node_parent_dir: Option<String>,
    ) -> MockBootstrapNode {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let delegate = SubstratumMockNode::start(ports, index, host_node_parent_dir);
            let nodes_arc = Arc::new(Mutex::new(vec![]));
            let name = delegate.name().to_string();
            let node_reference = delegate.node_reference();
            let nodes_arc_ext = nodes_arc.clone();
            tx.send((name, node_reference, nodes_arc_ext)).unwrap();
            let masquerader = JsonMasquerader::new();
            loop {
                Self::receive_and_respond_to_gossip(&delegate, &masquerader, nodes_arc.clone());
            }
        });
        let (name, node_reference, nodes_arc) = rx.recv().unwrap();
        let mbn = MockBootstrapNode {
            name: name.to_string(),
            node_reference,
            nodes_arc,
        };
        mbn
    }

    pub fn originating_node_key(&self) -> PublicKey {
        let nodes = self.nodes_arc.lock().unwrap();
        nodes.first().unwrap().public_key()
    }

    pub fn routing_node_keys(&self) -> Vec<PublicKey> {
        let nodes = self.nodes_arc.lock().unwrap();
        nodes
            .iter()
            .skip(1)
            .take(nodes.len() - 2)
            .map(GossipNodeRecord::public_key)
            .collect()
    }

    pub fn exit_node_key(&self) -> PublicKey {
        let nodes = self.nodes_arc.lock().unwrap();
        nodes.last().unwrap().public_key()
    }

    fn receive_and_respond_to_gossip(
        delegate: &SubstratumMockNode,
        masquerader: &Masquerader,
        nodes_arc: Arc<Mutex<Vec<GossipNodeRecord>>>,
    ) {
        match delegate.wait_for_gossip(Duration::from_secs(3600)) {
            None => (),
            Some(gossip) => {
                if gossip.node_records.len() != 1 {
                    return;
                }
                let new_node_record = gossip.node_records.first().unwrap();
                let nodes = {
                    let mut nodes = nodes_arc.lock().unwrap();
                    if nodes
                        .iter()
                        .find(|node_ref_ref: &&GossipNodeRecord| {
                            node_ref_ref.public_key() == new_node_record.public_key()
                        })
                        .is_some()
                    {
                        return;
                    }
                    nodes.push(new_node_record.clone());
                    nodes.clone()
                };

                for target_node_idx in 0..nodes.len() {
                    let target_node = &nodes[target_node_idx];
                    let icp = Self::build_gossip(&nodes, &delegate.public_key(), target_node_idx);
                    let port = delegate.node_reference().node_addr.ports()[0];
                    let target_addr = SubstratumNodeUtils::socket_addr(
                        &target_node.inner.node_addr_opt.as_ref().unwrap(),
                        PortSelector::First,
                        "",
                    );
                    delegate
                        .transmit_package(
                            port,
                            icp,
                            masquerader,
                            &target_node.public_key(),
                            target_addr,
                        )
                        .unwrap();
                }
            }
        }
    }

    fn build_gossip(
        nodes: &Vec<GossipNodeRecord>,
        local_public_key: &PublicKey,
        target_node_idx: usize,
    ) -> IncipientCoresPackage {
        let target_node = &nodes[target_node_idx];
        let mut builder = GossipBuilder::new(None);
        for node_idx in 0..nodes.len() {
            let node = &nodes[node_idx];
            if Self::absdiff(target_node_idx, node_idx) > 1 {
                builder = builder.add_gnr(&Self::censor(&node))
            } else {
                builder = builder.add_gnr(&node)
            }
        }
        for idx in 0..nodes.len() {
            if idx > 0 {
                builder =
                    builder.add_connection(&nodes[idx].public_key(), &nodes[idx - 1].public_key());
            }
            if idx < (nodes.len() - 1) {
                builder =
                    builder.add_connection(&nodes[idx].public_key(), &nodes[idx + 1].public_key());
            }
        }
        builder.build_cores_package(local_public_key, &target_node.public_key())
    }

    fn censor(node: &GossipNodeRecord) -> GossipNodeRecord {
        GossipNodeRecord {
            inner: NodeRecordInner {
                public_key: node.public_key(),
                node_addr_opt: None,
                earning_wallet: node.inner.earning_wallet.clone(),
                consuming_wallet: node.inner.consuming_wallet.clone(),
                is_bootstrap_node: node.inner.is_bootstrap_node,
                neighbors: vec![],
                version: node.inner.version,
            },
            signatures: NodeSignatures {
                complete: CryptData::new(&[]),
                obscured: CryptData::new(&[]),
            },
        }
    }

    fn absdiff(x: usize, y: usize) -> usize {
        if x < y {
            y - x
        } else {
            x - y
        }
    }
}
