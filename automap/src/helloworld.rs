
fn helloworld() -> String {
    "Hello, world!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helloworld_works() {
        let result = helloworld();

        assert_eq! (result, "Hello, world!".to_string());
    }
}