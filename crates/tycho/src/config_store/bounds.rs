//! The bounds of `config/schema.cue`, checked again on decoded values: a file that matches its
//! hash may still have been written by something other than `cue export`.

use super::{RoutingTables, Thresholds, CLASSES_MAX_ITEMS, MODEL_MAX_BYTES, TIERS_MAX_ITEMS};

pub const SECONDS_MAX: u64 = 86_400;
pub const SLOTS_MAX: u64 = 64;
pub const ATTEMPT_CAP_MAX: u64 = 99;
pub const PORT_STEP_ATTEMPTS_MAX: u64 = 100;
pub const COUNT_THRESHOLD_MAX: u64 = 10_000;
pub const PERIOD_DAYS_MAX: u64 = 3_650;

fn within(name: &str, value: u64, max: u64) -> Result<(), String> {
    if value == 0 || value > max {
        return Err(format!("{name} is {value}; expected 1..={max}"));
    }
    Ok(())
}

/// `^[a-z0-9][a-z0-9.-]*$`, at most `MODEL_MAX_BYTES`.
fn is_model(model: &str) -> bool {
    let bytes = model.as_bytes();
    let allowed = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    bytes.len() <= MODEL_MAX_BYTES
        && bytes.first().is_some_and(allowed)
        && bytes
            .iter()
            .all(|byte| allowed(byte) || *byte == b'.' || *byte == b'-')
}

fn count(name: &str, length: usize, max: usize) -> Result<(), String> {
    within(
        name,
        u64::try_from(length).unwrap_or(u64::MAX),
        u64::try_from(max).unwrap_or(u64::MAX),
    )
}

pub fn check_routing(routing: &RoutingTables) -> Result<(), String> {
    count("classes", routing.classes.len(), CLASSES_MAX_ITEMS)?;
    count("tiers", routing.tiers.len(), TIERS_MAX_ITEMS)?;
    for (name, class) in &routing.classes {
        if !routing.tiers.contains_key(&class.minimum_tier) {
            return Err(format!("class {name} names a missing tier"));
        }
        within(
            &format!("classes.{name}.attempt_cap"),
            u64::from(class.attempt_cap),
            ATTEMPT_CAP_MAX,
        )?;
    }
    for (name, tier) in &routing.tiers {
        if !is_model(&tier.models.claude) || !is_model(&tier.models.codex) {
            return Err(format!(
                "tier {name} has a model name outside the model shape"
            ));
        }
        let missing = tier
            .fallback
            .as_ref()
            .is_some_and(|fallback| !routing.tiers.contains_key(fallback));
        if missing {
            return Err(format!("tier {name} falls back to a missing tier"));
        }
    }
    Ok(())
}

fn check_durations(thresholds: &Thresholds) -> Result<(), String> {
    let stall = thresholds.stall;
    let retry = thresholds.retry;
    let session = thresholds.session;
    let durations = [
        ("stall.silence_seconds", stall.silence_seconds),
        ("stall.progress_seconds", stall.progress_seconds),
        (
            "retry.backoff_initial_seconds",
            retry.backoff_initial_seconds,
        ),
        ("retry.backoff_max_seconds", retry.backoff_max_seconds),
        (
            "retry.slot_retry_delay_seconds",
            retry.slot_retry_delay_seconds,
        ),
        (
            "session.heartbeat_interval_seconds",
            session.heartbeat_interval_seconds,
        ),
        ("session.lease_fresh_seconds", session.lease_fresh_seconds),
        ("session.spawn_grace_seconds", session.spawn_grace_seconds),
        (
            "session.reconciler_interval_seconds",
            session.reconciler_interval_seconds,
        ),
    ];
    for (name, value) in durations {
        within(name, value, SECONDS_MAX)?;
    }
    Ok(())
}

fn check_counts(thresholds: &Thresholds) -> Result<(), String> {
    let retry = thresholds.retry;
    let counts = [
        (
            "retry.port_step_attempts_max",
            u64::from(retry.port_step_attempts_max),
            PORT_STEP_ATTEMPTS_MAX,
        ),
        (
            "retry.unit_attempt_cap",
            u64::from(retry.unit_attempt_cap),
            ATTEMPT_CAP_MAX,
        ),
        (
            "slots.control",
            u64::from(thresholds.slots.control),
            SLOTS_MAX,
        ),
        (
            "slots.worker",
            u64::from(thresholds.slots.worker),
            SLOTS_MAX,
        ),
    ];
    for (name, value, max) in counts {
        within(name, value, max)?;
    }
    let mandate = thresholds.mandate;
    let optional = [
        (
            "mandate.convention_citations_min",
            mandate.convention_citations_min,
            COUNT_THRESHOLD_MAX,
        ),
        (
            "mandate.petition_repeat_count",
            mandate.petition_repeat_count,
            COUNT_THRESHOLD_MAX,
        ),
        (
            "mandate.convention_held_period_days",
            mandate.convention_held_period_days,
            PERIOD_DAYS_MAX,
        ),
        (
            "mandate.review_period_days",
            mandate.review_period_days,
            PERIOD_DAYS_MAX,
        ),
    ];
    for (name, value, max) in optional {
        if let Some(value) = value {
            within(name, u64::from(value), max)?;
        }
    }
    Ok(())
}

pub fn check_thresholds(thresholds: &Thresholds) -> Result<(), String> {
    check_durations(thresholds)?;
    check_counts(thresholds)?;
    let stall = thresholds.stall;
    let retry = thresholds.retry;
    let session = thresholds.session;
    if stall.progress_seconds <= stall.silence_seconds {
        return Err(
            "stall.progress_seconds (T2) must exceed stall.silence_seconds (T1)".to_string(),
        );
    }
    if retry.backoff_max_seconds < retry.backoff_initial_seconds {
        return Err("retry.backoff_max_seconds is below retry.backoff_initial_seconds".to_string());
    }
    if session.lease_fresh_seconds <= session.heartbeat_interval_seconds {
        return Err("session.lease_fresh_seconds must exceed the heartbeat interval".to_string());
    }
    if retry.backoff_factor != 2 {
        return Err("retry.backoff_factor must be 2; the spine implements doubling".to_string());
    }
    if !(session.rollover_fraction > 0.0 && session.rollover_fraction < 1.0) {
        return Err("session.rollover_fraction is outside (0, 1)".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_store::FactoryConfig;
    use tycho_types::task_packet::RoutingName;

    fn thresholds() -> Thresholds {
        FactoryConfig::embedded().unwrap().thresholds.value
    }

    fn routing() -> RoutingTables {
        FactoryConfig::embedded().unwrap().routing.value
    }

    #[test]
    fn the_embedded_values_pass() {
        assert_eq!(check_thresholds(&thresholds()), Ok(()));
        assert_eq!(check_routing(&routing()), Ok(()));
    }

    fn set(thresholds: &mut Thresholds, field: &str, value: u64) {
        let narrow = || u16::try_from(value).unwrap();
        match field {
            "silence" => thresholds.stall.silence_seconds = value,
            "progress" => thresholds.stall.progress_seconds = value,
            "backoff_initial" => thresholds.retry.backoff_initial_seconds = value,
            "backoff_max" => thresholds.retry.backoff_max_seconds = value,
            "slot_retry" => thresholds.retry.slot_retry_delay_seconds = value,
            "heartbeat" => thresholds.session.heartbeat_interval_seconds = value,
            "lease" => thresholds.session.lease_fresh_seconds = value,
            "spawn_grace" => thresholds.session.spawn_grace_seconds = value,
            "reconciler" => thresholds.session.reconciler_interval_seconds = value,
            "port_step" => thresholds.retry.port_step_attempts_max = u32::from(narrow()),
            "unit_cap" => thresholds.retry.unit_attempt_cap = narrow(),
            "control" => thresholds.slots.control = narrow(),
            "worker" => thresholds.slots.worker = narrow(),
            other => panic!("no field {other}"),
        }
    }

    #[test]
    fn every_threshold_bound_is_refused_one_past_and_at_zero() {
        let fields = [
            ("silence", SECONDS_MAX),
            ("progress", SECONDS_MAX),
            ("backoff_initial", SECONDS_MAX),
            ("backoff_max", SECONDS_MAX),
            ("slot_retry", SECONDS_MAX),
            ("heartbeat", SECONDS_MAX),
            ("lease", SECONDS_MAX),
            ("spawn_grace", SECONDS_MAX),
            ("reconciler", SECONDS_MAX),
            ("port_step", PORT_STEP_ATTEMPTS_MAX),
            ("unit_cap", ATTEMPT_CAP_MAX),
            ("control", SLOTS_MAX),
            ("worker", SLOTS_MAX),
        ];
        for (field, max) in fields {
            for value in [0, max + 1] {
                let mut edited = thresholds();
                set(&mut edited, field, value);
                assert!(check_thresholds(&edited).is_err(), "{field} = {value}");
            }
        }
    }

    #[test]
    fn mandate_thresholds_are_bounded_when_set() {
        let mut edited = thresholds();
        edited.mandate.review_period_days = Some(3_650);
        assert_eq!(check_thresholds(&edited), Ok(()));
        for value in [0, 3_651] {
            edited.mandate.review_period_days = Some(value);
            assert!(check_thresholds(&edited).is_err(), "{value}");
        }
        let mut edited = thresholds();
        edited.mandate.petition_repeat_count = Some(10_001);
        assert!(check_thresholds(&edited).is_err());
    }

    #[test]
    fn relations_factor_and_rollover_are_refused() {
        let mut lease = thresholds();
        lease.session.lease_fresh_seconds = lease.session.heartbeat_interval_seconds;
        let mut stall = thresholds();
        stall.stall.progress_seconds = stall.stall.silence_seconds;
        let mut backoff = thresholds();
        backoff.retry.backoff_max_seconds = backoff.retry.backoff_initial_seconds - 1;
        let mut factor = thresholds();
        factor.retry.backoff_factor = 3;
        for edited in [lease, stall, backoff, factor] {
            assert!(check_thresholds(&edited).is_err(), "{edited:?}");
        }
        for fraction in [0.0, 1.0, -0.1, f64::NAN] {
            let mut edited = thresholds();
            edited.session.rollover_fraction = fraction;
            assert!(check_thresholds(&edited).is_err(), "{fraction}");
        }
    }

    #[test]
    fn class_caps_and_model_names_are_bounded() {
        let implement = RoutingName::parse("implement").unwrap();
        for cap in [0, 100] {
            let mut edited = routing();
            edited.classes.get_mut(&implement).unwrap().attempt_cap = cap;
            assert!(check_routing(&edited).is_err(), "{cap}");
        }
        let standard = RoutingName::parse("standard").unwrap();
        for model in [
            "",
            "Sonnet",
            "-sonnet",
            "son net",
            &"m".repeat(MODEL_MAX_BYTES + 1),
        ] {
            let mut edited = routing();
            edited.tiers.get_mut(&standard).unwrap().models.codex = model.to_string();
            assert!(check_routing(&edited).is_err(), "{model:?}");
        }
        let mut edited = routing();
        edited.tiers.get_mut(&standard).unwrap().models.claude = "claude-sonnet-4.5".to_string();
        assert_eq!(check_routing(&edited), Ok(()));
    }
}
