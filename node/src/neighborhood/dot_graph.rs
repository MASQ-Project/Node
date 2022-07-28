// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::node_addr::NodeAddr;
use std::fmt::Write;

pub trait DotRenderable {
    fn render(&self) -> String;
}

pub struct NodeRenderableInner {
    pub version: u32,
    pub accepts_connections: bool,
    pub routes_data: bool,
}

pub struct NodeRenderable {
    pub inner: Option<NodeRenderableInner>,
    pub public_key: PublicKey,
    pub node_addr: Option<NodeAddr>,
    pub known_source: bool,
    pub known_target: bool,
    pub is_present: bool,
}

impl DotRenderable for NodeRenderable {
    fn render(&self) -> String {
        let mut result = String::new();
        write!(result, "\"{}\"", self.public_key).expect("write failed");
        write!(result, "{}", &self.render_label()).expect("write failed");
        if !self.is_present {
            write!(result, " [shape=none]").expect("write failed");
        } else if self.known_target {
            write!(result, " [shape=box]").expect("write failed");
        }
        if self.known_source {
            write!(result, " [style=filled]").expect("write failed");
        }
        write!(result, ";").expect("write failed");
        result
    }
}

impl NodeRenderable {
    fn render_label(&self) -> String {
        let inner_string = match &self.inner {
            Some(inner) => format!(
                "{}{} v{}\\n",
                if inner.accepts_connections { "A" } else { "a" },
                if inner.routes_data { "R" } else { "r" },
                inner.version,
            ),
            None => String::new(),
        };
        let public_key_str = format!("{}", self.public_key);
        let public_key_trunc = if public_key_str.len() > 8 {
            &public_key_str[0..8]
        } else {
            &public_key_str
        };
        let node_addr_string = match self.node_addr {
            None => String::new(),
            Some(ref na) => format!("\\n{}", na),
        };

        format!(
            " [label=\"{}{}{}\"]",
            inner_string, public_key_trunc, node_addr_string,
        )
    }
}

pub struct EdgeRenderable {
    pub from: PublicKey,
    pub to: PublicKey,
}

impl DotRenderable for EdgeRenderable {
    fn render(&self) -> String {
        let mut result = String::new();
        write!(result, "\"{}\" -> \"{}\";", self.from, self.to).expect("write failed");
        result
    }
}

pub fn render_dot_graph(renderables: Vec<Box<dyn DotRenderable>>) -> String {
    let mut result = String::from("digraph db {");
    for renderable in renderables {
        write!(result, " {}", renderable.render()).expect("write failed");
    }
    result.push_str(" }");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_string_contains;

    #[test]
    fn truncation_works_for_long_keys() {
        let public_key = PublicKey::new(&b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..]);
        let public_key_64 = format!("{}", public_key);
        let public_key_trunc = String::from(&public_key_64[0..8]);
        let node = NodeRenderable {
            inner: Some(NodeRenderableInner {
                version: 1,
                accepts_connections: true,
                routes_data: true,
            }),
            public_key: public_key.clone(),
            node_addr: None,
            known_source: false,
            known_target: false,
            is_present: true,
        };

        let result = render_dot_graph(vec![Box::new(node)]);

        assert_string_contains(
            &result,
            &format!(
                "\"{}\" [label=\"AR v1\\n{}\"];",
                public_key_64, public_key_trunc
            ),
        );
    }

    #[test]
    fn truncation_works_for_short_keys() {
        let public_key = PublicKey::new(&b"ABC"[..]);
        let public_key_64 = format!("{}", public_key);
        let node = NodeRenderable {
            inner: Some(NodeRenderableInner {
                version: 1,
                accepts_connections: false,
                routes_data: false,
            }),
            public_key: public_key.clone(),
            node_addr: None,
            known_source: false,
            known_target: false,
            is_present: true,
        };

        let result = render_dot_graph(vec![Box::new(node)]);

        assert_string_contains(
            &result,
            &format!(
                "\"{}\" [label=\"ar v1\\n{}\"];",
                public_key_64, public_key_64
            ),
        );
    }
}
