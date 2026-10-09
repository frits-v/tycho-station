//! Synthetic target project for the tycho-station evaluation harness.

pub fn answer() -> u32 {
    0
}

pub fn greeting() -> String {
    String::new()
}

pub fn find_tag(id: u32) -> Vec<&'static str> {
    if id == 1 {
        vec!["known"]
    } else {
        Vec::new()
    }
}

pub fn has_tag(id: u32) -> bool {
    !find_tag(id).is_empty()
}

pub enum LookupOutcome {
    Found(&'static str),
    NotFound,
}

pub fn find_label(id: u32) -> LookupOutcome {
    if id == 1 {
        LookupOutcome::Found("known")
    } else {
        LookupOutcome::NotFound
    }
}

pub fn has_label(id: u32) -> bool {
    matches!(find_label(id), LookupOutcome::Found(_))
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

    #[test]
    fn has_tag_is_false_when_unknown() {
        assert!(!has_tag(99));
    }

    #[test]
    fn has_label_is_false_when_unknown() {
        assert!(!has_label(99));
    }
}
