// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate multinode_integration_tests_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;

use multinode_integration_tests_lib::substratum_cores_client::SubstratumCoresClient;
use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use node_lib::discriminator::DiscriminatorFactory;
use node_lib::json_masquerader::JsonMasquerader;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use multinode_integration_tests_lib::substratum_node::NodeStartupConfig;
use node_lib::json_discriminator_factory::JsonDiscriminatorFactory;

#[test]
fn relay_cores_package () {
    let mut cluster = SubstratumNodeCluster::new (vec! (NodeStartupConfig::new (vec! (4663))));
    let cryptde = CryptDENull::new ();
    let factories: Vec<Box<DiscriminatorFactory>> = vec! (Box::new (JsonDiscriminatorFactory::new ()));
    let masquerader = JsonMasquerader::new ();
    let mut server = SubstratumCoresServer::new (4663, factories, &cryptde);
    let mut client = SubstratumCoresClient::new (server.local_addr (), &cryptde);
    let mut route = Route::new (
        vec! (
            RouteSegment::new (vec! (&cryptde.public_key(), &cryptde.public_key()), Component::Neighborhood)
        ),
        &cryptde
    ).unwrap ();
    let payload = String::from ("Booga booga!");
    let incipient = IncipientCoresPackage::new (route.clone (), payload, &cryptde.public_key());

    client.transmit_package(incipient, &masquerader);
    let expired: ExpiredCoresPackage = server.wait_for_package ();

    cluster.stop_all ();
    route.shift (&cryptde.private_key (), &cryptde);
    assert_eq! (expired.remaining_route, route);
    assert_eq! (serde_cbor::de::from_slice::<String> (&expired.payload.data[..]).unwrap (), String::from ("Booga booga!"));
}
