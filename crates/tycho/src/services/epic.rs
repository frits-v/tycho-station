//! The Epic virtual object: goal, work units, the two budget ledgers and the slot counters.
//! `reserve` and `settle` never block; a full slot answers "retry later".

use std::collections::BTreeMap;
use std::fmt;

use restate_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tycho_types::envelope::{RecordId, ShortText};
use tycho_types::service::{Attempt, TaskId, WorkUnitId};

use crate::config::spine;
use crate::config_store::SlotCounts;
use crate::services::{
    refuse, Ports, CODE_BAD_REQUEST, CODE_CONFLICT, CODE_INTERNAL, CODE_NOT_FOUND,
};

const STATE_KEY: &str = "epic";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    /// Seat capacity, in tokens.
    Seat,
    /// Metered spend, in micro-dollars.
    Metered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotLevel {
    Control,
    Worker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    pub limit: u64,
    pub reserved: u64,
    pub charged: u64,
}

impl Ledger {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            reserved: 0,
            charged: 0,
        }
    }

    const fn available(&self) -> u64 {
        self.limit
            .saturating_sub(self.reserved)
            .saturating_sub(self.charged)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slots {
    pub limit: u16,
    pub used: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub level: SlotLevel,
    pub ledger: LedgerKind,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpicState {
    pub goal: ShortText,
    pub units: Vec<WorkUnitId>,
    pub seat: Ledger,
    pub metered: Ledger,
    pub control_slots: Slots,
    pub worker_slots: Slots,
    pub cases_in_force: Vec<RecordId>,
    /// Keyed by `<task id>.<attempt>`.
    pub reservations: BTreeMap<String, Reservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub goal: ShortText,
    pub seat_limit: u64,
    pub metered_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveRequest {
    pub task: TaskId,
    pub attempt: u16,
    pub level: SlotLevel,
    pub ledger: LedgerKind,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAnswer {
    Granted,
    /// The same reservation is already held; nothing changed.
    AlreadyHeld,
    /// The slot for the level is full; the caller re-sends itself after a delay.
    RetryLater,
    /// The ledger cannot cover the amount; settlement never frees budget, so this is final.
    BudgetExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettleRequest {
    pub task: TaskId,
    pub attempt: u16,
    /// Usage observed at exit, in the reservation's ledger unit.
    pub observed: u64,
    /// False when no session ever started for the reservation; nothing is charged then.
    pub spawned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settled", rename_all = "snake_case")]
pub enum SettleAnswer {
    Charged {
        amount: u64,
    },
    /// Nothing held under this key: never reserved, or settled already.
    NothingHeld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddUnitAnswer {
    Added,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpicError {
    NotStarted,
    GoalMismatch,
    Attempt(u16),
    TooManyUnits,
    TooManyReservations,
    Overflow(&'static str),
}

impl fmt::Display for EpicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => formatter.write_str("the epic has not been started"),
            Self::GoalMismatch => formatter.write_str("the epic was started with another goal"),
            Self::Attempt(value) => write!(formatter, "attempt {value} is out of range"),
            Self::TooManyUnits => write!(
                formatter,
                "the epic holds {} work units already",
                spine::EPIC_UNITS_MAX
            ),
            Self::TooManyReservations => write!(
                formatter,
                "the epic holds {} reservations already",
                spine::EPIC_RESERVATIONS_MAX
            ),
            Self::Overflow(field) => write!(formatter, "{field} would overflow"),
        }
    }
}

impl EpicError {
    const fn code(&self) -> u16 {
        match self {
            Self::NotStarted => CODE_NOT_FOUND,
            Self::GoalMismatch => CODE_CONFLICT,
            Self::Attempt(_) | Self::TooManyUnits | Self::TooManyReservations => CODE_BAD_REQUEST,
            Self::Overflow(_) => CODE_INTERNAL,
        }
    }
}

fn reservation_key(task: &TaskId, attempt: u16) -> Result<String, EpicError> {
    let attempt = Attempt::new(attempt).map_err(|_| EpicError::Attempt(attempt))?;
    Ok(format!("{task}.{}", attempt.get()))
}

/// A started epic, or the same epic again when the goal matches.
pub fn start(
    current: Option<EpicState>,
    request: StartRequest,
    slots: SlotCounts,
) -> Result<EpicState, EpicError> {
    if let Some(state) = current {
        if state.goal != request.goal {
            return Err(EpicError::GoalMismatch);
        }
        return Ok(state);
    }
    Ok(EpicState {
        goal: request.goal,
        units: Vec::new(),
        seat: Ledger::new(request.seat_limit),
        metered: Ledger::new(request.metered_limit),
        control_slots: Slots {
            limit: slots.control,
            used: 0,
        },
        worker_slots: Slots {
            limit: slots.worker,
            used: 0,
        },
        cases_in_force: Vec::new(),
        reservations: BTreeMap::new(),
    })
}

pub fn add_unit(state: &mut EpicState, unit: WorkUnitId) -> Result<AddUnitAnswer, EpicError> {
    if state.units.contains(&unit) {
        return Ok(AddUnitAnswer::AlreadyPresent);
    }
    if state.units.len() >= spine::EPIC_UNITS_MAX {
        return Err(EpicError::TooManyUnits);
    }
    state.units.push(unit);
    Ok(AddUnitAnswer::Added)
}

impl EpicState {
    const fn slots_mut(&mut self, level: SlotLevel) -> &mut Slots {
        match level {
            SlotLevel::Control => &mut self.control_slots,
            SlotLevel::Worker => &mut self.worker_slots,
        }
    }

    const fn ledger_mut(&mut self, kind: LedgerKind) -> &mut Ledger {
        match kind {
            LedgerKind::Seat => &mut self.seat,
            LedgerKind::Metered => &mut self.metered,
        }
    }
}

/// Budget before slots: an exhausted ledger is final, a full slot is not.
pub fn reserve(
    state: &mut EpicState,
    request: &ReserveRequest,
) -> Result<ReserveAnswer, EpicError> {
    let key = reservation_key(&request.task, request.attempt)?;
    if state.reservations.contains_key(&key) {
        return Ok(ReserveAnswer::AlreadyHeld);
    }
    if state.reservations.len() >= spine::EPIC_RESERVATIONS_MAX {
        return Err(EpicError::TooManyReservations);
    }
    if state.ledger_mut(request.ledger).available() < request.amount {
        return Ok(ReserveAnswer::BudgetExhausted);
    }
    let slots = state.slots_mut(request.level);
    if slots.used >= slots.limit {
        return Ok(ReserveAnswer::RetryLater);
    }
    slots.used = slots
        .used
        .checked_add(1)
        .ok_or(EpicError::Overflow("slot counter"))?;
    let ledger = state.ledger_mut(request.ledger);
    ledger.reserved = ledger
        .reserved
        .checked_add(request.amount)
        .ok_or(EpicError::Overflow("reserved budget"))?;
    state.reservations.insert(
        key,
        Reservation {
            level: request.level,
            ledger: request.ledger,
            amount: request.amount,
        },
    );
    Ok(ReserveAnswer::Granted)
}

/// Charges the larger of reservation and usage, or nothing if no session started; frees the slot.
pub fn settle(state: &mut EpicState, request: &SettleRequest) -> Result<SettleAnswer, EpicError> {
    let key = reservation_key(&request.task, request.attempt)?;
    let Some(reservation) = state.reservations.remove(&key) else {
        return Ok(SettleAnswer::NothingHeld);
    };
    let slots = state.slots_mut(reservation.level);
    slots.used = slots
        .used
        .checked_sub(1)
        .ok_or(EpicError::Overflow("slot counter below zero"))?;
    let amount = if request.spawned {
        reservation.amount.max(request.observed)
    } else {
        0
    };
    let ledger = state.ledger_mut(reservation.ledger);
    ledger.reserved = ledger
        .reserved
        .checked_sub(reservation.amount)
        .ok_or(EpicError::Overflow("reserved budget below zero"))?;
    ledger.charged = ledger
        .charged
        .checked_add(amount)
        .ok_or(EpicError::Overflow("charged budget"))?;
    Ok(SettleAnswer::Charged { amount })
}

fn terminal(error: &EpicError) -> HandlerError {
    refuse(error.code(), error.to_string())
}

/// Holds the slot counts a newly started epic gets.
#[derive(Debug, Clone, Copy)]
pub struct Epic {
    slots: SlotCounts,
}

impl Epic {
    #[must_use]
    pub fn new(ports: &Ports) -> Self {
        Self {
            slots: ports.config.thresholds.value.slots,
        }
    }
}

#[restate_sdk::object]
impl Epic {
    #[handler(ingress_private)]
    async fn start(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<StartRequest>,
    ) -> HandlerResult<Json<EpicState>> {
        let current = object_context.get::<Json<EpicState>>(STATE_KEY).await?;
        let state = start(
            current.map(Json::into_inner),
            request.into_inner(),
            self.slots,
        )
        .map_err(|error| terminal(&error))?;
        object_context.set(STATE_KEY, Json(state.clone()));
        Ok(Json(state))
    }

    #[handler(ingress_private)]
    async fn add_unit(
        &self,
        object_context: ObjectContext<'_>,
        unit: Json<WorkUnitId>,
    ) -> HandlerResult<Json<AddUnitAnswer>> {
        let mut state = load(&object_context).await?;
        let answer = add_unit(&mut state, unit.into_inner()).map_err(|error| terminal(&error))?;
        object_context.set(STATE_KEY, Json(state));
        Ok(Json(answer))
    }

    #[handler(ingress_private)]
    async fn reserve(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<ReserveRequest>,
    ) -> HandlerResult<Json<ReserveAnswer>> {
        let mut state = load(&object_context).await?;
        let answer =
            reserve(&mut state, &request.into_inner()).map_err(|error| terminal(&error))?;
        object_context.set(STATE_KEY, Json(state));
        Ok(Json(answer))
    }

    #[handler(ingress_private)]
    async fn settle(
        &self,
        object_context: ObjectContext<'_>,
        request: Json<SettleRequest>,
    ) -> HandlerResult<Json<SettleAnswer>> {
        let mut state = load(&object_context).await?;
        let answer = settle(&mut state, &request.into_inner()).map_err(|error| terminal(&error))?;
        object_context.set(STATE_KEY, Json(state));
        Ok(Json(answer))
    }

    #[handler]
    async fn status(
        &self,
        shared_context: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<EpicState>>> {
        let state = shared_context.get::<Json<EpicState>>(STATE_KEY).await?;
        Ok(Json(state.map(Json::into_inner)))
    }
}

async fn load(object_context: &ObjectContext<'_>) -> Result<EpicState, HandlerError> {
    object_context
        .get::<Json<EpicState>>(STATE_KEY)
        .await?
        .map(Json::into_inner)
        .ok_or_else(|| terminal(&EpicError::NotStarted))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOTS: SlotCounts = SlotCounts {
        control: 2,
        worker: 2,
    };

    fn started(seat: u64, metered: u64) -> EpicState {
        start(
            None,
            StartRequest {
                goal: ShortText::parse("split orders").unwrap(),
                seat_limit: seat,
                metered_limit: metered,
            },
            SLOTS,
        )
        .unwrap()
    }

    fn request(task: &str, level: SlotLevel, amount: u64) -> ReserveRequest {
        ReserveRequest {
            task: TaskId::parse(task).unwrap(),
            attempt: 1,
            level,
            ledger: LedgerKind::Seat,
            amount,
        }
    }

    fn settle_request(task: &str, observed: u64) -> SettleRequest {
        SettleRequest {
            task: TaskId::parse(task).unwrap(),
            attempt: 1,
            observed,
            spawned: true,
        }
    }

    #[test]
    fn start_is_idempotent_for_the_same_goal_only() {
        let state = started(100, 0);
        assert_eq!(
            start(
                Some(state.clone()),
                StartRequest {
                    goal: state.goal.clone(),
                    seat_limit: 1,
                    metered_limit: 1
                },
                SLOTS
            ),
            Ok(state.clone())
        );
        let other = StartRequest {
            goal: ShortText::parse("other").unwrap(),
            seat_limit: 1,
            metered_limit: 1,
        };
        assert_eq!(
            start(Some(state), other, SLOTS),
            Err(EpicError::GoalMismatch)
        );
    }

    #[test]
    fn add_unit_is_idempotent_and_bounded() {
        let mut state = started(100, 0);
        let unit = WorkUnitId::parse("wu01").unwrap();
        assert_eq!(add_unit(&mut state, unit.clone()), Ok(AddUnitAnswer::Added));
        assert_eq!(
            add_unit(&mut state, unit),
            Ok(AddUnitAnswer::AlreadyPresent)
        );
        for index in 1..spine::EPIC_UNITS_MAX {
            let unit = WorkUnitId::parse(&format!("wu{index:03}")).unwrap();
            assert_eq!(add_unit(&mut state, unit), Ok(AddUnitAnswer::Added));
        }
        let over = WorkUnitId::parse("wu-over").unwrap();
        assert_eq!(add_unit(&mut state, over), Err(EpicError::TooManyUnits));
    }

    #[test]
    fn reserve_grants_until_the_slot_is_full() {
        let mut state = started(1_000, 0);
        assert_eq!(
            reserve(&mut state, &request("t1", SlotLevel::Worker, 10)),
            Ok(ReserveAnswer::Granted)
        );
        assert_eq!(
            reserve(&mut state, &request("t2", SlotLevel::Worker, 10)),
            Ok(ReserveAnswer::Granted)
        );
        assert_eq!(
            reserve(&mut state, &request("t3", SlotLevel::Worker, 10)),
            Ok(ReserveAnswer::RetryLater)
        );
        assert_eq!(state.worker_slots.used, SLOTS.worker);
        assert_eq!(state.seat.reserved, 20);
        assert_eq!(
            reserve(&mut state, &request("t3", SlotLevel::Control, 10)),
            Ok(ReserveAnswer::Granted)
        );
    }

    #[test]
    fn reserve_is_idempotent_per_task_and_attempt() {
        let mut state = started(1_000, 0);
        let first = request("t1", SlotLevel::Worker, 10);
        assert_eq!(reserve(&mut state, &first), Ok(ReserveAnswer::Granted));
        assert_eq!(reserve(&mut state, &first), Ok(ReserveAnswer::AlreadyHeld));
        assert_eq!(state.worker_slots.used, 1);
        assert_eq!(state.seat.reserved, 10);
        let second = ReserveRequest {
            attempt: 2,
            ..first
        };
        assert_eq!(reserve(&mut state, &second), Ok(ReserveAnswer::Granted));
    }

    #[test]
    fn reserve_answers_budget_exhausted_before_retry_later() {
        let mut state = started(15, 0);
        assert_eq!(
            reserve(&mut state, &request("t1", SlotLevel::Worker, 10)),
            Ok(ReserveAnswer::Granted)
        );
        assert_eq!(
            reserve(&mut state, &request("t2", SlotLevel::Worker, 10)),
            Ok(ReserveAnswer::BudgetExhausted)
        );
        let metered = ReserveRequest {
            ledger: LedgerKind::Metered,
            ..request("t3", SlotLevel::Worker, 1)
        };
        assert_eq!(
            reserve(&mut state, &metered),
            Ok(ReserveAnswer::BudgetExhausted)
        );
    }

    #[test]
    fn reserve_rejects_an_attempt_out_of_range() {
        let mut state = started(15, 0);
        let zero = ReserveRequest {
            attempt: 0,
            ..request("t1", SlotLevel::Worker, 1)
        };
        assert_eq!(reserve(&mut state, &zero), Err(EpicError::Attempt(0)));
    }

    #[test]
    fn reserve_is_bounded_by_the_reservation_maximum() {
        let mut state = started(u64::MAX, 0);
        state.worker_slots.limit = u16::MAX;
        for index in 0..spine::EPIC_RESERVATIONS_MAX {
            let granted = reserve(
                &mut state,
                &request(&format!("t{index}"), SlotLevel::Worker, 1),
            );
            assert_eq!(granted, Ok(ReserveAnswer::Granted));
        }
        assert_eq!(
            reserve(&mut state, &request("over", SlotLevel::Worker, 1)),
            Err(EpicError::TooManyReservations)
        );
    }

    #[test]
    fn settle_charges_the_larger_of_reservation_and_usage() {
        let mut state = started(1_000, 0);
        reserve(&mut state, &request("low", SlotLevel::Worker, 100)).unwrap();
        reserve(&mut state, &request("high", SlotLevel::Worker, 100)).unwrap();
        assert_eq!(
            settle(&mut state, &settle_request("low", 30)),
            Ok(SettleAnswer::Charged { amount: 100 })
        );
        assert_eq!(
            settle(&mut state, &settle_request("high", 250)),
            Ok(SettleAnswer::Charged { amount: 250 })
        );
        assert_eq!(state.seat.reserved, 0);
        assert_eq!(state.seat.charged, 350);
        assert_eq!(state.worker_slots.used, 0);
        assert!(state.reservations.is_empty());
    }

    #[test]
    fn settle_frees_the_slot_for_a_waiting_reservation() {
        let mut state = started(1_000, 0);
        reserve(&mut state, &request("t1", SlotLevel::Worker, 1)).unwrap();
        reserve(&mut state, &request("t2", SlotLevel::Worker, 1)).unwrap();
        let waiting = request("t3", SlotLevel::Worker, 1);
        assert_eq!(reserve(&mut state, &waiting), Ok(ReserveAnswer::RetryLater));
        settle(&mut state, &settle_request("t1", 0)).unwrap();
        assert_eq!(reserve(&mut state, &waiting), Ok(ReserveAnswer::Granted));
    }

    #[test]
    fn a_reservation_that_never_spawned_settles_at_zero() {
        let mut state = started(1_000, 0);
        reserve(&mut state, &request("t1", SlotLevel::Worker, 100)).unwrap();
        let unspawned = SettleRequest {
            spawned: false,
            ..settle_request("t1", 0)
        };
        assert_eq!(
            settle(&mut state, &unspawned),
            Ok(SettleAnswer::Charged { amount: 0 })
        );
        assert_eq!((state.seat.charged, state.seat.reserved), (0, 0));
        assert_eq!(state.worker_slots.used, 0);
    }

    #[test]
    fn a_second_settle_changes_nothing() {
        let mut state = started(1_000, 0);
        reserve(&mut state, &request("t1", SlotLevel::Worker, 10)).unwrap();
        settle(&mut state, &settle_request("t1", 0)).unwrap();
        let after_first = state.clone();
        assert_eq!(
            settle(&mut state, &settle_request("t1", 0)),
            Ok(SettleAnswer::NothingHeld)
        );
        assert_eq!(state, after_first);
    }

    #[test]
    fn an_overcharge_exhausts_the_ledger() {
        let mut state = started(100, 0);
        reserve(&mut state, &request("t1", SlotLevel::Worker, 10)).unwrap();
        settle(&mut state, &settle_request("t1", 500)).unwrap();
        assert_eq!(state.seat.available(), 0);
        assert_eq!(
            reserve(&mut state, &request("t2", SlotLevel::Worker, 1)),
            Ok(ReserveAnswer::BudgetExhausted)
        );
    }
}
