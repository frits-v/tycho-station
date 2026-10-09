// Spine numbers from design section 7; placeholders until the harness measures them.
package config

thresholds: #Thresholds & {
	stall: {
		silence_seconds:  300
		progress_seconds: 900
	}
	slots: {
		control: 2
		worker:  2
	}
	retry: {
		backoff_initial_seconds: 10
		backoff_max_seconds:     300
		backoff_factor:          2
		// With the backoff above, about 35 minutes before a port step turns terminal.
		port_step_attempts_max:   12
		slot_retry_delay_seconds: 10
		unit_attempt_cap:         3
	}
	session: {
		heartbeat_interval_seconds:  10
		lease_fresh_seconds:         30
		spawn_grace_seconds:         60
		reconciler_interval_seconds: 30
		rollover_fraction:           0.6
	}
	mandate: {
		convention_citations_min:    null
		petition_repeat_count:       null
		convention_held_period_days: null
		review_period_days:          null
	}
}
