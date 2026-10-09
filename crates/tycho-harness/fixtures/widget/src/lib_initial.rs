//! Synthetic target project for the tycho-station evaluation harness.

pub fn answer() -> u32 {
    0
}

pub fn greeting() -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_is_42() {
        assert_eq!(answer(), 42);
    }

    #[test]
    fn answer_times_two_is_84() {
        assert_eq!(answer() * 2, 84);
    }

    #[test]
    fn greeting_contains_hello() {
        assert!(greeting().contains("Hello"));
    }
}
