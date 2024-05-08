// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PublicKey;
use masq_lib::node_addr::NodeAddr;
use std::fmt::Write as _;

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
        let _ = write!(result, "\"{}\"", self.public_key);
        let _ = write!(result, "{}", &self.render_label());
        if !self.is_present {
            let _ = write!(result, " [shape=none]");
        } else if self.known_target {
            let _ = write!(result, " [shape=box]");
        }
        if self.known_source {
            let _ = write!(result, " [style=filled]");
        }
        let _ = write!(result, ";");
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
        let _ = write!(result, "\"{}\" -> \"{}\";", self.from, self.to);
        result
    }
}

pub fn render_dot_graph(renderables: Vec<Box<dyn DotRenderable>>) -> String {
    let mut result = String::from("digraph db {");
    for renderable in renderables {
        let _ = write!(result, " {}", renderable.render());
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
