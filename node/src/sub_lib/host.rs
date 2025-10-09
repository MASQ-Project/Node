use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub port: u16,
}

impl Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}:{}", self.name, self.port)
    }
}

impl Host {
    pub fn new(name: &str, port: u16) -> Host {
        Host {
            name: name.to_string(),
            port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        let subject = Host {
            name: "example.com".to_string(),
            port: 8080,
        };

        let result = format!("{}", subject);

        assert_eq!(result, "example.com:8080".to_string());
    }
}