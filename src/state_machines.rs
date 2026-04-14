//! Application state machine simulation.
//!
//! Define business logic as typed state machines. Prove all transitions
//! are valid, no invalid states are reachable, and the machine always
//! terminates or reaches an accepting state.
//!
//! This extends the convergence platform's verification capability from
//! infrastructure (Terraform JSON invariants) to application logic. If
//! we can prove infrastructure by defining types and checking invariants,
//! we can prove APPLICATION LOGIC the same way.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// A state in the machine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct State(pub String);

impl State {
    /// Create a new state.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

/// An event/action that triggers a transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Event(pub String);

impl Event {
    /// Create a new event.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

/// A typed state machine definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachine {
    pub name: String,
    pub states: BTreeSet<State>,
    pub initial: State,
    pub accepting: BTreeSet<State>,
    pub transitions: Vec<Transition>,
}

/// A single transition in the state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from: State,
    pub event: Event,
    pub to: State,
    /// Human-readable guard condition description.
    pub guard: Option<String>,
}

/// Invariants a state machine can satisfy.
pub enum StateMachineInvariant {
    /// Every state is reachable from the initial state.
    AllStatesReachable,
    /// No dead-end states (every non-accepting state has at least one outgoing transition).
    NoDeadEnds,
    /// Deterministic: no two transitions from the same state with the same event.
    Deterministic,
    /// Every path from initial eventually reaches an accepting state (no non-accepting cycles).
    AlwaysTerminates,
    /// No self-loops (no transition where from == to).
    NoSelfLoops,
}

/// Check a state machine invariant, returning `Ok(())` on success or
/// an error message describing the violation.
///
/// # Errors
///
/// Returns a description of which states/transitions violate the invariant.
pub fn check_invariant(
    machine: &StateMachine,
    invariant: &StateMachineInvariant,
) -> Result<(), String> {
    match invariant {
        StateMachineInvariant::AllStatesReachable => check_all_reachable(machine),
        StateMachineInvariant::NoDeadEnds => check_no_dead_ends(machine),
        StateMachineInvariant::Deterministic => check_deterministic(machine),
        StateMachineInvariant::AlwaysTerminates => check_always_terminates(machine),
        StateMachineInvariant::NoSelfLoops => check_no_self_loops(machine),
    }
}

/// BFS from the initial state. Check that every state in `machine.states`
/// is reachable.
fn check_all_reachable(machine: &StateMachine) -> Result<(), String> {
    let reachable = reachable_states(machine);
    let unreachable: BTreeSet<_> = machine.states.difference(&reachable).collect();
    if unreachable.is_empty() {
        Ok(())
    } else {
        let names: Vec<_> = unreachable.iter().map(|s| s.0.as_str()).collect();
        Err(format!("unreachable states: {}", names.join(", ")))
    }
}

/// Compute all states reachable from the initial state via BFS.
fn reachable_states(machine: &StateMachine) -> BTreeSet<State> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    // Build adjacency: from -> [to, ...]
    let mut adj: HashMap<&State, Vec<&State>> = HashMap::new();
    for t in &machine.transitions {
        adj.entry(&t.from).or_default().push(&t.to);
    }

    visited.insert(machine.initial.clone());
    queue.push_back(&machine.initial);

    while let Some(current) = queue.pop_front() {
        if let Some(neighbors) = adj.get(current) {
            for &next in neighbors {
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
    }

    visited
}

/// Every non-accepting state must have at least one outgoing transition.
fn check_no_dead_ends(machine: &StateMachine) -> Result<(), String> {
    let states_with_outgoing: HashSet<&State> =
        machine.transitions.iter().map(|t| &t.from).collect();

    let dead_ends: Vec<_> = machine
        .states
        .iter()
        .filter(|s| !machine.accepting.contains(*s) && !states_with_outgoing.contains(*s))
        .map(|s| s.0.as_str())
        .collect();

    if dead_ends.is_empty() {
        Ok(())
    } else {
        Err(format!("dead-end states: {}", dead_ends.join(", ")))
    }
}

/// No two transitions from the same state with the same event.
fn check_deterministic(machine: &StateMachine) -> Result<(), String> {
    let mut seen: HashSet<(&State, &Event)> = HashSet::new();
    let mut duplicates = Vec::new();

    for t in &machine.transitions {
        if !seen.insert((&t.from, &t.event)) {
            duplicates.push(format!("({}, {})", t.from.0, t.event.0));
        }
    }

    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "non-deterministic (state, event) pairs: {}",
            duplicates.join(", ")
        ))
    }
}

/// Every path from initial must eventually reach an accepting state.
///
/// Implementation: find all strongly connected components (SCCs) that are
/// reachable from the initial state. If any SCC contains no accepting
/// state and has a cycle (size > 1, or self-loop), the machine can get
/// stuck in a non-accepting cycle.
///
/// Additionally, any reachable non-accepting dead-end (no outgoing
/// transitions) means the machine can get stuck.
fn check_always_terminates(machine: &StateMachine) -> Result<(), String> {
    let reachable = reachable_states(machine);

    // Build adjacency for reachable states only.
    let mut adj: BTreeMap<&State, Vec<&State>> = BTreeMap::new();
    for t in &machine.transitions {
        if reachable.contains(&t.from) {
            adj.entry(&t.from).or_default().push(&t.to);
        }
    }

    // Check dead-end non-accepting reachable states.
    for state in &reachable {
        if !machine.accepting.contains(state) && !adj.contains_key(state) {
            return Err(format!(
                "non-accepting dead-end state '{}' is reachable",
                state.0
            ));
        }
    }

    // Find SCCs via Tarjan's algorithm.
    let sccs = tarjan_scc(machine, &reachable);

    // Check each SCC: if it has a cycle and no accepting state, the
    // machine can loop forever without terminating.
    for scc in &sccs {
        let has_accepting = scc.iter().any(|s| machine.accepting.contains(s));
        if has_accepting {
            continue;
        }

        let is_cycle = if scc.len() > 1 {
            true
        } else {
            // Single-node SCC: it's a cycle only if there's a self-loop.
            let single = &scc[0];
            adj.get(single)
                .is_some_and(|targets| targets.contains(&single))
        };

        if is_cycle {
            let names: Vec<_> = scc.iter().map(|s| s.0.as_str()).collect();
            return Err(format!(
                "non-accepting cycle: {{{}}}",
                names.join(", ")
            ));
        }
    }

    Ok(())
}

/// Tarjan's SCC algorithm. Returns a list of strongly connected components,
/// each represented as a vector of states.
fn tarjan_scc<'a>(
    machine: &'a StateMachine,
    reachable: &BTreeSet<State>,
) -> Vec<Vec<&'a State>> {
    // Build adjacency using references to machine.states via transitions.
    let mut adj: HashMap<&State, Vec<&State>> = HashMap::new();
    for t in &machine.transitions {
        if reachable.contains(&t.from) && reachable.contains(&t.to) {
            adj.entry(&t.from).or_default().push(&t.to);
        }
    }

    // Collect all reachable state references from machine.states.
    let nodes: Vec<&State> = machine
        .states
        .iter()
        .filter(|s| reachable.contains(*s))
        .collect();

    let mut index_counter: usize = 0;
    let mut stack: Vec<&State> = Vec::new();
    let mut on_stack: HashSet<&State> = HashSet::new();
    let mut indices: HashMap<&State, usize> = HashMap::new();
    let mut lowlinks: HashMap<&State, usize> = HashMap::new();
    let mut result: Vec<Vec<&State>> = Vec::new();

    for node in &nodes {
        if !indices.contains_key(*node) {
            strongconnect(
                *node,
                &adj,
                &mut index_counter,
                &mut stack,
                &mut on_stack,
                &mut indices,
                &mut lowlinks,
                &mut result,
            );
        }
    }

    return result;

    fn strongconnect<'a>(
        v: &'a State,
        adj: &HashMap<&'a State, Vec<&'a State>>,
        index_counter: &mut usize,
        stack: &mut Vec<&'a State>,
        on_stack: &mut HashSet<&'a State>,
        indices: &mut HashMap<&'a State, usize>,
        lowlinks: &mut HashMap<&'a State, usize>,
        result: &mut Vec<Vec<&'a State>>,
    ) {
        indices.insert(v, *index_counter);
        lowlinks.insert(v, *index_counter);
        *index_counter += 1;
        stack.push(v);
        on_stack.insert(v);

        if let Some(neighbors) = adj.get(v) {
            for &w in neighbors {
                if !indices.contains_key(w) {
                    strongconnect(w, adj, index_counter, stack, on_stack, indices, lowlinks, result);
                    let lw = lowlinks[w];
                    let lv = lowlinks[v];
                    lowlinks.insert(v, lv.min(lw));
                } else if on_stack.contains(w) {
                    let iw = indices[w];
                    let lv = lowlinks[v];
                    lowlinks.insert(v, lv.min(iw));
                }
            }
        }

        if lowlinks[v] == indices[v] {
            let mut scc = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack.remove(w);
                scc.push(w);
                if std::ptr::eq(w, v) {
                    break;
                }
            }
            result.push(scc);
        }
    }
}

/// No transition where `from == to`.
fn check_no_self_loops(machine: &StateMachine) -> Result<(), String> {
    let loops: Vec<_> = machine
        .transitions
        .iter()
        .filter(|t| t.from == t.to)
        .map(|t| format!("({}, {})", t.from.0, t.event.0))
        .collect();

    if loops.is_empty() {
        Ok(())
    } else {
        Err(format!("self-loops: {}", loops.join(", ")))
    }
}

/// Simulate a sequence of events through the machine, returning the
/// state trace (including the initial state) or an error if an invalid
/// transition is encountered.
///
/// # Errors
///
/// Returns a message if no valid transition exists for an event at the
/// current state.
pub fn simulate_execution(
    machine: &StateMachine,
    events: &[Event],
) -> Result<Vec<State>, String> {
    let mut current = machine.initial.clone();
    let mut trace = vec![current.clone()];

    // Build lookup: (from, event) -> to
    let mut lookup: HashMap<(&State, &Event), &State> = HashMap::new();
    for t in &machine.transitions {
        lookup.insert((&t.from, &t.event), &t.to);
    }

    for (i, event) in events.iter().enumerate() {
        match lookup.get(&(&current, event)) {
            Some(&next) => {
                current = next.clone();
                trace.push(current.clone());
            }
            None => {
                return Err(format!(
                    "no transition from state '{}' on event '{}' (step {})",
                    current.0, event.0, i
                ));
            }
        }
    }

    Ok(trace)
}

// ═══════════════════════════════════════════════════════════════════
// Common state machine builders
// ═══════════════════════════════════════════════════════════════════

/// E-commerce order lifecycle state machine.
///
/// States: created, confirmed, shipped, delivered, cancelled
/// Transitions: created->confirmed->shipped->delivered,
///              created->cancelled, confirmed->cancelled
#[must_use]
pub fn order_lifecycle() -> StateMachine {
    let created = State::new("created");
    let confirmed = State::new("confirmed");
    let shipped = State::new("shipped");
    let delivered = State::new("delivered");
    let cancelled = State::new("cancelled");

    StateMachine {
        name: "order_lifecycle".to_string(),
        states: [&created, &confirmed, &shipped, &delivered, &cancelled]
            .into_iter()
            .cloned()
            .collect(),
        initial: created.clone(),
        accepting: [delivered.clone(), cancelled.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: created.clone(),
                event: Event::new("confirm"),
                to: confirmed.clone(),
                guard: Some("payment_valid".to_string()),
            },
            Transition {
                from: created.clone(),
                event: Event::new("cancel"),
                to: cancelled.clone(),
                guard: None,
            },
            Transition {
                from: confirmed.clone(),
                event: Event::new("ship"),
                to: shipped.clone(),
                guard: Some("inventory_available".to_string()),
            },
            Transition {
                from: confirmed.clone(),
                event: Event::new("cancel"),
                to: cancelled.clone(),
                guard: None,
            },
            Transition {
                from: shipped.clone(),
                event: Event::new("deliver"),
                to: delivered.clone(),
                guard: None,
            },
        ],
    }
}

/// User authentication state machine.
///
/// States: anonymous, authenticated, authorized, session_expired, locked_out
/// Transitions: anonymous->authenticated->authorized->session_expired->anonymous,
///              authenticated->locked_out
#[must_use]
pub fn user_auth() -> StateMachine {
    let anonymous = State::new("anonymous");
    let authenticated = State::new("authenticated");
    let authorized = State::new("authorized");
    let session_expired = State::new("session_expired");
    let locked_out = State::new("locked_out");

    StateMachine {
        name: "user_auth".to_string(),
        states: [
            &anonymous,
            &authenticated,
            &authorized,
            &session_expired,
            &locked_out,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: anonymous.clone(),
        accepting: [anonymous.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: anonymous.clone(),
                event: Event::new("login"),
                to: authenticated.clone(),
                guard: Some("credentials_valid".to_string()),
            },
            Transition {
                from: authenticated.clone(),
                event: Event::new("authorize"),
                to: authorized.clone(),
                guard: Some("permissions_granted".to_string()),
            },
            Transition {
                from: authenticated.clone(),
                event: Event::new("lockout"),
                to: locked_out.clone(),
                guard: Some("too_many_failures".to_string()),
            },
            Transition {
                from: authorized.clone(),
                event: Event::new("expire"),
                to: session_expired.clone(),
                guard: None,
            },
            Transition {
                from: session_expired.clone(),
                event: Event::new("logout"),
                to: anonymous.clone(),
                guard: None,
            },
            Transition {
                from: locked_out.clone(),
                event: Event::new("unlock"),
                to: anonymous.clone(),
                guard: Some("admin_intervention".to_string()),
            },
        ],
    }
}

/// Deployment pipeline state machine — the convergence loop itself.
///
/// States: declared, simulated, proven, rendered, deployed, verified, converged
/// Transitions follow the strict convergence pipeline.
#[must_use]
pub fn deployment_pipeline() -> StateMachine {
    let declared = State::new("declared");
    let simulated = State::new("simulated");
    let proven = State::new("proven");
    let rendered = State::new("rendered");
    let deployed = State::new("deployed");
    let verified = State::new("verified");
    let converged = State::new("converged");

    StateMachine {
        name: "deployment_pipeline".to_string(),
        states: [
            &declared, &simulated, &proven, &rendered, &deployed, &verified, &converged,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: declared.clone(),
        accepting: [converged.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: declared.clone(),
                event: Event::new("simulate"),
                to: simulated.clone(),
                guard: Some("types_valid".to_string()),
            },
            Transition {
                from: simulated.clone(),
                event: Event::new("prove"),
                to: proven.clone(),
                guard: Some("invariants_checked".to_string()),
            },
            Transition {
                from: proven.clone(),
                event: Event::new("render"),
                to: rendered.clone(),
                guard: Some("backend_available".to_string()),
            },
            Transition {
                from: rendered.clone(),
                event: Event::new("deploy"),
                to: deployed.clone(),
                guard: Some("certificates_valid".to_string()),
            },
            Transition {
                from: deployed.clone(),
                event: Event::new("verify"),
                to: verified.clone(),
                guard: Some("health_checks_pass".to_string()),
            },
            Transition {
                from: verified.clone(),
                event: Event::new("converge"),
                to: converged.clone(),
                guard: Some("drift_zero".to_string()),
            },
        ],
    }
}

/// CI/CD pipeline state machine.
///
/// States: idle, building, testing, staging, approved, releasing, released, failed
#[must_use]
pub fn cicd_pipeline() -> StateMachine {
    let idle = State::new("idle");
    let building = State::new("building");
    let testing = State::new("testing");
    let staging = State::new("staging");
    let approved = State::new("approved");
    let releasing = State::new("releasing");
    let released = State::new("released");
    let failed = State::new("failed");

    StateMachine {
        name: "cicd_pipeline".to_string(),
        states: [
            &idle, &building, &testing, &staging, &approved, &releasing, &released, &failed,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: idle.clone(),
        accepting: [released.clone(), failed.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: idle.clone(),
                event: Event::new("push"),
                to: building.clone(),
                guard: None,
            },
            Transition {
                from: building.clone(),
                event: Event::new("build_success"),
                to: testing.clone(),
                guard: None,
            },
            Transition {
                from: building.clone(),
                event: Event::new("build_fail"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: testing.clone(),
                event: Event::new("tests_pass"),
                to: staging.clone(),
                guard: None,
            },
            Transition {
                from: testing.clone(),
                event: Event::new("tests_fail"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: staging.clone(),
                event: Event::new("approve"),
                to: approved.clone(),
                guard: Some("reviewer_approved".to_string()),
            },
            Transition {
                from: staging.clone(),
                event: Event::new("reject"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: approved.clone(),
                event: Event::new("release"),
                to: releasing.clone(),
                guard: None,
            },
            Transition {
                from: releasing.clone(),
                event: Event::new("release_success"),
                to: released.clone(),
                guard: None,
            },
            Transition {
                from: releasing.clone(),
                event: Event::new("release_fail"),
                to: failed.clone(),
                guard: None,
            },
        ],
    }
}

/// Customer onboarding state machine.
///
/// States: prospect, registered, verified, onboarded, active, churned
#[must_use]
pub fn customer_onboarding() -> StateMachine {
    let prospect = State::new("prospect");
    let registered = State::new("registered");
    let verified = State::new("verified");
    let onboarded = State::new("onboarded");
    let active = State::new("active");
    let churned = State::new("churned");

    StateMachine {
        name: "customer_onboarding".to_string(),
        states: [
            &prospect, &registered, &verified, &onboarded, &active, &churned,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: prospect.clone(),
        accepting: [active.clone(), churned.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: prospect.clone(),
                event: Event::new("register"),
                to: registered.clone(),
                guard: None,
            },
            Transition {
                from: registered.clone(),
                event: Event::new("verify_email"),
                to: verified.clone(),
                guard: Some("email_confirmed".to_string()),
            },
            Transition {
                from: verified.clone(),
                event: Event::new("complete_profile"),
                to: onboarded.clone(),
                guard: Some("profile_complete".to_string()),
            },
            Transition {
                from: onboarded.clone(),
                event: Event::new("activate"),
                to: active.clone(),
                guard: Some("first_action_taken".to_string()),
            },
            Transition {
                from: active.clone(),
                event: Event::new("churn"),
                to: churned.clone(),
                guard: Some("inactive_90_days".to_string()),
            },
            Transition {
                from: registered.clone(),
                event: Event::new("abandon"),
                to: churned.clone(),
                guard: Some("no_verification_7_days".to_string()),
            },
        ],
    }
}

/// Payment processing state machine for composition with order lifecycle.
///
/// States: pending, authorized, captured, refunded, failed
#[must_use]
pub fn payment_processing() -> StateMachine {
    let pending = State::new("pending");
    let authorized = State::new("authorized");
    let captured = State::new("captured");
    let refunded = State::new("refunded");
    let failed = State::new("failed");

    StateMachine {
        name: "payment_processing".to_string(),
        states: [&pending, &authorized, &captured, &refunded, &failed]
            .into_iter()
            .cloned()
            .collect(),
        initial: pending.clone(),
        accepting: [captured.clone(), refunded.clone(), failed.clone()]
            .into_iter()
            .collect(),
        transitions: vec![
            Transition {
                from: pending.clone(),
                event: Event::new("authorize"),
                to: authorized.clone(),
                guard: Some("funds_available".to_string()),
            },
            Transition {
                from: pending.clone(),
                event: Event::new("decline"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: authorized.clone(),
                event: Event::new("capture"),
                to: captured.clone(),
                guard: None,
            },
            Transition {
                from: authorized.clone(),
                event: Event::new("void"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: captured.clone(),
                event: Event::new("refund"),
                to: refunded.clone(),
                guard: Some("within_refund_window".to_string()),
            },
        ],
    }
}

/// Shipping state machine for composition with order lifecycle.
///
/// States: awaiting, picked, packed, in_transit, delivered, returned
#[must_use]
pub fn shipping() -> StateMachine {
    let awaiting = State::new("awaiting");
    let picked = State::new("picked");
    let packed = State::new("packed");
    let in_transit = State::new("in_transit");
    let delivered = State::new("delivered");
    let returned = State::new("returned");

    StateMachine {
        name: "shipping".to_string(),
        states: [&awaiting, &picked, &packed, &in_transit, &delivered, &returned]
            .into_iter()
            .cloned()
            .collect(),
        initial: awaiting.clone(),
        accepting: [delivered.clone(), returned.clone()].into_iter().collect(),
        transitions: vec![
            Transition {
                from: awaiting.clone(),
                event: Event::new("pick"),
                to: picked.clone(),
                guard: None,
            },
            Transition {
                from: picked.clone(),
                event: Event::new("pack"),
                to: packed.clone(),
                guard: None,
            },
            Transition {
                from: packed.clone(),
                event: Event::new("ship"),
                to: in_transit.clone(),
                guard: Some("carrier_assigned".to_string()),
            },
            Transition {
                from: in_transit.clone(),
                event: Event::new("deliver"),
                to: delivered.clone(),
                guard: None,
            },
            Transition {
                from: in_transit.clone(),
                event: Event::new("return"),
                to: returned.clone(),
                guard: Some("recipient_refused".to_string()),
            },
        ],
    }
}

/// Microservice saga pattern state machine.
///
/// Models a distributed transaction with compensation.
///
/// States: initiated, order_created, payment_charged, inventory_reserved,
///         shipping_scheduled, completed, compensating, compensated, failed
#[must_use]
pub fn saga_pattern() -> StateMachine {
    let initiated = State::new("initiated");
    let order_created = State::new("order_created");
    let payment_charged = State::new("payment_charged");
    let inventory_reserved = State::new("inventory_reserved");
    let shipping_scheduled = State::new("shipping_scheduled");
    let completed = State::new("completed");
    let compensating = State::new("compensating");
    let compensated = State::new("compensated");
    let failed = State::new("failed");

    StateMachine {
        name: "saga_pattern".to_string(),
        states: [
            &initiated,
            &order_created,
            &payment_charged,
            &inventory_reserved,
            &shipping_scheduled,
            &completed,
            &compensating,
            &compensated,
            &failed,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: initiated.clone(),
        accepting: [completed.clone(), compensated.clone(), failed.clone()]
            .into_iter()
            .collect(),
        transitions: vec![
            Transition {
                from: initiated.clone(),
                event: Event::new("create_order"),
                to: order_created.clone(),
                guard: None,
            },
            Transition {
                from: order_created.clone(),
                event: Event::new("charge_payment"),
                to: payment_charged.clone(),
                guard: Some("payment_service_available".to_string()),
            },
            Transition {
                from: payment_charged.clone(),
                event: Event::new("reserve_inventory"),
                to: inventory_reserved.clone(),
                guard: Some("stock_available".to_string()),
            },
            Transition {
                from: inventory_reserved.clone(),
                event: Event::new("schedule_shipping"),
                to: shipping_scheduled.clone(),
                guard: Some("carrier_available".to_string()),
            },
            Transition {
                from: shipping_scheduled.clone(),
                event: Event::new("complete"),
                to: completed.clone(),
                guard: None,
            },
            // Compensation path
            Transition {
                from: order_created.clone(),
                event: Event::new("payment_failed"),
                to: compensating.clone(),
                guard: None,
            },
            Transition {
                from: payment_charged.clone(),
                event: Event::new("inventory_failed"),
                to: compensating.clone(),
                guard: None,
            },
            Transition {
                from: inventory_reserved.clone(),
                event: Event::new("shipping_failed"),
                to: compensating.clone(),
                guard: None,
            },
            Transition {
                from: compensating.clone(),
                event: Event::new("compensate_success"),
                to: compensated.clone(),
                guard: None,
            },
            Transition {
                from: compensating.clone(),
                event: Event::new("compensate_failed"),
                to: failed.clone(),
                guard: None,
            },
        ],
    }
}

/// Database migration state machine (mirrors transitions.rs pattern).
///
/// States: pending, backing_up, migrating, validating, migrated, rolling_back, rolled_back, failed
#[must_use]
pub fn database_migration() -> StateMachine {
    let pending = State::new("pending");
    let backing_up = State::new("backing_up");
    let migrating = State::new("migrating");
    let validating = State::new("validating");
    let migrated = State::new("migrated");
    let rolling_back = State::new("rolling_back");
    let rolled_back = State::new("rolled_back");
    let failed = State::new("failed");

    StateMachine {
        name: "database_migration".to_string(),
        states: [
            &pending,
            &backing_up,
            &migrating,
            &validating,
            &migrated,
            &rolling_back,
            &rolled_back,
            &failed,
        ]
        .into_iter()
        .cloned()
        .collect(),
        initial: pending.clone(),
        accepting: [migrated.clone(), rolled_back.clone(), failed.clone()]
            .into_iter()
            .collect(),
        transitions: vec![
            Transition {
                from: pending.clone(),
                event: Event::new("start_backup"),
                to: backing_up.clone(),
                guard: None,
            },
            Transition {
                from: backing_up.clone(),
                event: Event::new("backup_complete"),
                to: migrating.clone(),
                guard: Some("backup_verified".to_string()),
            },
            Transition {
                from: backing_up.clone(),
                event: Event::new("backup_failed"),
                to: failed.clone(),
                guard: None,
            },
            Transition {
                from: migrating.clone(),
                event: Event::new("migration_complete"),
                to: validating.clone(),
                guard: None,
            },
            Transition {
                from: migrating.clone(),
                event: Event::new("migration_failed"),
                to: rolling_back.clone(),
                guard: None,
            },
            Transition {
                from: validating.clone(),
                event: Event::new("validation_pass"),
                to: migrated.clone(),
                guard: Some("schema_matches".to_string()),
            },
            Transition {
                from: validating.clone(),
                event: Event::new("validation_fail"),
                to: rolling_back.clone(),
                guard: None,
            },
            Transition {
                from: rolling_back.clone(),
                event: Event::new("rollback_complete"),
                to: rolled_back.clone(),
                guard: None,
            },
            Transition {
                from: rolling_back.clone(),
                event: Event::new("rollback_failed"),
                to: failed.clone(),
                guard: None,
            },
        ],
    }
}

/// Compose multiple state machines by prefixing each state with the machine
/// name, yielding a single machine. This is useful for verifying cross-domain
/// composed systems (e.g., order + payment + shipping).
///
/// The composed machine has a synthetic initial state that can transition
/// to each sub-machine's initial state, and all sub-machine accepting states
/// are accepting in the composed machine.
#[must_use]
pub fn compose(machines: &[&StateMachine]) -> StateMachine {
    let mut states = BTreeSet::new();
    let mut accepting = BTreeSet::new();
    let mut transitions = Vec::new();

    let composed_initial = State::new("composed_initial");
    states.insert(composed_initial.clone());

    for machine in machines {
        let prefix = &machine.name;

        for state in &machine.states {
            let prefixed = State::new(&format!("{prefix}.{}", state.0));
            states.insert(prefixed);
        }

        for a in &machine.accepting {
            accepting.insert(State::new(&format!("{prefix}.{}", a.0)));
        }

        for t in &machine.transitions {
            transitions.push(Transition {
                from: State::new(&format!("{prefix}.{}", t.from.0)),
                event: Event::new(&format!("{prefix}.{}", t.event.0)),
                to: State::new(&format!("{prefix}.{}", t.to.0)),
                guard: t.guard.clone(),
            });
        }

        // Transition from composed_initial to each sub-machine's initial.
        transitions.push(Transition {
            from: composed_initial.clone(),
            event: Event::new(&format!("start_{prefix}")),
            to: State::new(&format!("{prefix}.{}", machine.initial.0)),
            guard: None,
        });
    }

    StateMachine {
        name: "composed".to_string(),
        states,
        initial: composed_initial,
        accepting,
        transitions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_lifecycle_is_well_formed() {
        let m = order_lifecycle();
        assert_eq!(m.states.len(), 5);
        assert_eq!(m.transitions.len(), 5);
        assert!(m.states.contains(&m.initial));
        for a in &m.accepting {
            assert!(m.states.contains(a));
        }
    }

    #[test]
    fn user_auth_is_well_formed() {
        let m = user_auth();
        assert_eq!(m.states.len(), 5);
        assert!(m.states.contains(&m.initial));
    }

    #[test]
    fn deployment_pipeline_is_well_formed() {
        let m = deployment_pipeline();
        assert_eq!(m.states.len(), 7);
        assert_eq!(m.transitions.len(), 6);
    }

    #[test]
    fn simulate_valid_order() {
        let m = order_lifecycle();
        let events = vec![
            Event::new("confirm"),
            Event::new("ship"),
            Event::new("deliver"),
        ];
        let trace = simulate_execution(&m, &events).unwrap();
        assert_eq!(trace.len(), 4);
        assert_eq!(trace.last().unwrap(), &State::new("delivered"));
    }

    #[test]
    fn simulate_invalid_event_errors() {
        let m = order_lifecycle();
        let events = vec![Event::new("ship")]; // can't ship from created
        let result = simulate_execution(&m, &events);
        assert!(result.is_err());
    }

    #[test]
    fn reachable_states_from_initial() {
        let m = order_lifecycle();
        let reachable = reachable_states(&m);
        assert_eq!(reachable, m.states);
    }

    #[test]
    fn compose_creates_prefixed_states() {
        let order = order_lifecycle();
        let payment = payment_processing();
        let composed = compose(&[&order, &payment]);

        assert!(composed.states.contains(&State::new("order_lifecycle.created")));
        assert!(composed.states.contains(&State::new("payment_processing.pending")));
        assert!(composed.states.contains(&State::new("composed_initial")));
    }
}
