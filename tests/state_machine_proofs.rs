//! Application state machine proofs — business logic as typed convergence.
//!
//! 30 tests proving:
//! - State machine definition invariants (6 tests)
//! - Simulation correctness (4 tests)
//! - Convergence loop as state machine (5 tests)
//! - Proptest exhaustive proofs (5 tests)
//! - Cross-domain composed proofs (10 tests)

use pangea_sim::state_machines::{
    check_invariant, cicd_pipeline, compose, customer_onboarding, database_migration,
    deployment_pipeline, order_lifecycle, payment_processing, saga_pattern, shipping,
    simulate_execution, user_auth, Event, State, StateMachine, StateMachineInvariant, Transition,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

// ═══════════════════════════════════════════════════════════════════
// State machine definition proofs (1-6)
// ═══════════════════════════════════════════════════════════════════

/// 1. Order lifecycle has all states reachable from initial.
#[test]
fn proof_order_lifecycle_all_reachable() {
    let m = order_lifecycle();
    assert!(
        check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok(),
        "all order lifecycle states must be reachable from 'created'"
    );
}

/// 2. Order lifecycle has no dead ends.
#[test]
fn proof_order_lifecycle_no_dead_ends() {
    let m = order_lifecycle();
    assert!(
        check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok(),
        "every non-accepting state must have an outgoing transition"
    );
}

/// 3. Order lifecycle is deterministic.
#[test]
fn proof_order_lifecycle_deterministic() {
    let m = order_lifecycle();
    assert!(
        check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok(),
        "no two transitions from same state with same event"
    );
}

/// 4. User auth machine has all states reachable.
#[test]
fn proof_user_auth_all_reachable() {
    let m = user_auth();
    assert!(
        check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok(),
        "all user auth states must be reachable from 'anonymous'"
    );
}

/// 5. Deployment pipeline has all states reachable.
#[test]
fn proof_deployment_pipeline_all_reachable() {
    let m = deployment_pipeline();
    assert!(
        check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok(),
        "all deployment pipeline states must be reachable from 'declared'"
    );
}

/// 6. Deployment pipeline is deterministic.
#[test]
fn proof_deployment_pipeline_deterministic() {
    let m = deployment_pipeline();
    assert!(
        check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok(),
        "deployment pipeline must be deterministic"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Simulation proofs (7-10)
// ═══════════════════════════════════════════════════════════════════

/// 7. Valid event sequence reaches accepting state.
#[test]
fn proof_valid_sequence_reaches_accepting() {
    let m = order_lifecycle();
    let events = vec![
        Event::new("confirm"),
        Event::new("ship"),
        Event::new("deliver"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    let final_state = trace.last().unwrap();
    assert!(
        m.accepting.contains(final_state),
        "final state '{}' should be accepting",
        final_state.0
    );
}

/// 8. Invalid event returns error.
#[test]
fn proof_invalid_event_returns_error() {
    let m = order_lifecycle();
    // Can't ship directly from 'created'
    let events = vec![Event::new("ship")];
    let result = simulate_execution(&m, &events);
    assert!(
        result.is_err(),
        "shipping from 'created' should fail"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("no transition"),
        "error should mention 'no transition': {err}"
    );
}

/// 9. Empty event sequence stays at initial.
#[test]
fn proof_empty_events_stays_at_initial() {
    let m = order_lifecycle();
    let trace = simulate_execution(&m, &[]).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0], m.initial);
}

/// 10. Simulation trace length = events + 1 (includes initial).
#[test]
fn proof_trace_length_is_events_plus_one() {
    let m = deployment_pipeline();
    let events = vec![
        Event::new("simulate"),
        Event::new("prove"),
        Event::new("render"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    assert_eq!(
        trace.len(),
        events.len() + 1,
        "trace should include initial state plus one state per event"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Convergence loop as state machine (11-15)
// ═══════════════════════════════════════════════════════════════════

/// 11. The convergence loop satisfies AllStatesReachable.
#[test]
fn proof_convergence_loop_all_reachable() {
    let m = deployment_pipeline();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
}

/// 12. The convergence loop satisfies NoDeadEnds.
#[test]
fn proof_convergence_loop_no_dead_ends() {
    let m = deployment_pipeline();
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
}

/// 13. The convergence loop satisfies Deterministic.
#[test]
fn proof_convergence_loop_deterministic() {
    let m = deployment_pipeline();
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
}

/// 14. The convergence loop satisfies AlwaysTerminates.
#[test]
fn proof_convergence_loop_always_terminates() {
    let m = deployment_pipeline();
    assert!(
        check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok(),
        "convergence pipeline must always reach 'converged'"
    );
}

/// 15. The convergence loop IS a valid state machine — the platform's own
/// workflow proven correct by construction.
#[test]
fn proof_convergence_loop_is_valid_state_machine() {
    let m = deployment_pipeline();

    // All five invariants hold
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoSelfLoops).is_ok());

    // Full simulation reaches converged
    let events = vec![
        Event::new("simulate"),
        Event::new("prove"),
        Event::new("render"),
        Event::new("deploy"),
        Event::new("verify"),
        Event::new("converge"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("converged"));
    assert!(m.accepting.contains(trace.last().unwrap()));
}

// ═══════════════════════════════════════════════════════════════════
// Proptest proofs (16-20)
// ═══════════════════════════════════════════════════════════════════

/// Helper: generate a random fully-connected state machine with `n` states.
/// Every state is reachable because we create a chain from s0 -> s1 -> ... -> s(n-1).
fn make_fully_connected_machine(n: usize) -> StateMachine {
    assert!(n >= 2, "need at least 2 states");

    let states: Vec<State> = (0..n).map(|i| State::new(&format!("s{i}"))).collect();
    let mut transitions = Vec::new();

    // Chain: s0 -> s1 -> ... -> s(n-1)
    for i in 0..n - 1 {
        transitions.push(Transition {
            from: states[i].clone(),
            event: Event::new(&format!("e{i}_to_{}", i + 1)),
            to: states[i + 1].clone(),
            guard: None,
        });
    }

    let mut accepting = BTreeSet::new();
    accepting.insert(states[n - 1].clone());

    StateMachine {
        name: "random_chain".to_string(),
        states: states.into_iter().collect(),
        initial: State::new("s0"),
        accepting,
        transitions,
    }
}

/// 16. Random valid state machines with N states satisfy AllStatesReachable.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn proof_random_machines_all_reachable(n in 2..20_usize) {
        let m = make_fully_connected_machine(n);
        prop_assert!(
            check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok(),
            "chain machine with {n} states should have all states reachable"
        );
    }
}

/// 17. Deterministic machines never have ambiguous transitions.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn proof_deterministic_machines_no_ambiguity(n in 2..20_usize) {
        let m = make_fully_connected_machine(n);
        // Chain machines are always deterministic: unique events per state.
        prop_assert!(
            check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok(),
            "chain machine should be deterministic"
        );
    }
}

/// 18. Adding a transition never removes reachability.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn proof_adding_transition_preserves_reachability(
        n in 3..15_usize,
        extra_from in 0..15_usize,
        extra_to in 0..15_usize,
    ) {
        let mut m = make_fully_connected_machine(n);
        let from_idx = extra_from % n;
        let to_idx = extra_to % n;

        // Add an extra transition.
        m.transitions.push(Transition {
            from: State::new(&format!("s{from_idx}")),
            event: Event::new(&format!("extra_{from_idx}_{to_idx}")),
            to: State::new(&format!("s{to_idx}")),
            guard: None,
        });

        prop_assert!(
            check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok(),
            "adding a transition should never remove reachability"
        );
    }
}

/// 19. Removing a transition can create dead ends — detect them.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn proof_removing_transition_can_create_dead_ends(n in 3..15_usize) {
        let mut m = make_fully_connected_machine(n);

        // Remove the transition from the second-to-last non-accepting state.
        // This should create a dead end at state s(n-2) because its only
        // outgoing transition is to s(n-1).
        let remove_idx = n - 2; // transition index for s(n-2) -> s(n-1)
        m.transitions.remove(remove_idx);

        // s(n-2) is now a non-accepting state with no outgoing transitions = dead end.
        let result = check_invariant(&m, &StateMachineInvariant::NoDeadEnds);
        prop_assert!(
            result.is_err(),
            "removing s{remove_idx}'s only transition should create a dead end"
        );
    }
}

/// 20. State machine serialization roundtrip via serde.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn proof_serialization_roundtrip(n in 2..15_usize) {
        let m = make_fully_connected_machine(n);
        let json = serde_json::to_string(&m).unwrap();
        let m2: StateMachine = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(m.name, m2.name);
        prop_assert_eq!(m.states, m2.states);
        prop_assert_eq!(m.initial, m2.initial);
        prop_assert_eq!(m.accepting, m2.accepting);
        prop_assert_eq!(m.transitions.len(), m2.transitions.len());
    }
}

// ═══════════════════════════════════════════════════════════════════
// Cross-domain proofs (21-30)
// ═══════════════════════════════════════════════════════════════════

/// 21. E-commerce order + payment + shipping composed machine is valid.
#[test]
fn proof_ecommerce_composed_machine() {
    let order = order_lifecycle();
    let payment = payment_processing();
    let ship = shipping();
    let composed = compose(&[&order, &payment, &ship]);

    assert!(
        check_invariant(&composed, &StateMachineInvariant::AllStatesReachable).is_ok(),
        "all states in composed e-commerce machine should be reachable"
    );
    assert!(
        check_invariant(&composed, &StateMachineInvariant::Deterministic).is_ok(),
        "composed e-commerce machine should be deterministic"
    );
    assert!(
        check_invariant(&composed, &StateMachineInvariant::NoDeadEnds).is_ok(),
        "composed e-commerce machine should have no dead ends"
    );
}

/// 22. Microservice saga pattern as state machine — all invariants hold.
#[test]
fn proof_saga_pattern_all_invariants() {
    let m = saga_pattern();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoSelfLoops).is_ok());
}

/// 23. Database migration as state machine — matches transitions.rs pattern.
#[test]
fn proof_database_migration_state_machine() {
    let m = database_migration();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());

    // Simulate successful migration path
    let events = vec![
        Event::new("start_backup"),
        Event::new("backup_complete"),
        Event::new("migration_complete"),
        Event::new("validation_pass"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("migrated"));

    // Simulate rollback path
    let rollback_events = vec![
        Event::new("start_backup"),
        Event::new("backup_complete"),
        Event::new("migration_failed"),
        Event::new("rollback_complete"),
    ];
    let trace = simulate_execution(&m, &rollback_events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("rolled_back"));
}

/// 24. CI/CD pipeline as state machine.
#[test]
fn proof_cicd_pipeline_state_machine() {
    let m = cicd_pipeline();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());

    // Simulate happy path
    let events = vec![
        Event::new("push"),
        Event::new("build_success"),
        Event::new("tests_pass"),
        Event::new("approve"),
        Event::new("release"),
        Event::new("release_success"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("released"));

    // Simulate failure path
    let fail_events = vec![
        Event::new("push"),
        Event::new("build_fail"),
    ];
    let trace = simulate_execution(&m, &fail_events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("failed"));
}

/// 25. Customer onboarding as state machine.
#[test]
fn proof_customer_onboarding_state_machine() {
    let m = customer_onboarding();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());

    // Full onboarding path
    let events = vec![
        Event::new("register"),
        Event::new("verify_email"),
        Event::new("complete_profile"),
        Event::new("activate"),
    ];
    let trace = simulate_execution(&m, &events).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("active"));
}

/// 26. Saga pattern simulation — happy path and compensation.
#[test]
fn proof_saga_simulation_paths() {
    let m = saga_pattern();

    // Happy path
    let happy = vec![
        Event::new("create_order"),
        Event::new("charge_payment"),
        Event::new("reserve_inventory"),
        Event::new("schedule_shipping"),
        Event::new("complete"),
    ];
    let trace = simulate_execution(&m, &happy).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("completed"));

    // Compensation path: payment fails after order created
    let compensate = vec![
        Event::new("create_order"),
        Event::new("payment_failed"),
        Event::new("compensate_success"),
    ];
    let trace = simulate_execution(&m, &compensate).unwrap();
    assert_eq!(trace.last().unwrap(), &State::new("compensated"));
}

/// 27. Payment processing machine satisfies all invariants.
#[test]
fn proof_payment_processing_invariants() {
    let m = payment_processing();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoSelfLoops).is_ok());
}

/// 28. Shipping machine satisfies all invariants.
#[test]
fn proof_shipping_invariants() {
    let m = shipping();
    assert!(check_invariant(&m, &StateMachineInvariant::AllStatesReachable).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoDeadEnds).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::Deterministic).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::AlwaysTerminates).is_ok());
    assert!(check_invariant(&m, &StateMachineInvariant::NoSelfLoops).is_ok());
}

/// 29. Self-loop detection works: adding a self-loop is caught.
#[test]
fn proof_self_loop_detection() {
    let mut m = order_lifecycle();
    // Add a self-loop: created --noop--> created
    m.transitions.push(Transition {
        from: State::new("created"),
        event: Event::new("noop"),
        to: State::new("created"),
        guard: None,
    });

    let result = check_invariant(&m, &StateMachineInvariant::NoSelfLoops);
    assert!(result.is_err(), "self-loop should be detected");
    let err = result.unwrap_err();
    assert!(err.contains("created"), "error should reference the looping state: {err}");
}

/// 30. Non-determinism detection works: duplicate (state, event) is caught.
#[test]
fn proof_non_determinism_detection() {
    let mut m = order_lifecycle();
    // Add a duplicate: created --confirm--> shipped (conflicts with created --confirm--> confirmed)
    m.transitions.push(Transition {
        from: State::new("created"),
        event: Event::new("confirm"),
        to: State::new("shipped"),
        guard: None,
    });

    let result = check_invariant(&m, &StateMachineInvariant::Deterministic);
    assert!(result.is_err(), "duplicate (state, event) should be non-deterministic");
    let err = result.unwrap_err();
    assert!(
        err.contains("created") && err.contains("confirm"),
        "error should reference the conflicting pair: {err}"
    );
}
