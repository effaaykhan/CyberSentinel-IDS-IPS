//! The detection engine (**Phase 3**).
//!
//! Rule grouping by header, an `aho-corasick` multi-pattern scan over
//! `fast_pattern` content, then full evaluation of the surviving candidates
//! (content modifiers, `pcre`, `flow`, `flowbits`, sticky buffers, `byte_test`,
//! thresholds) — ending in a CyberSentinel `alert` event.
//!
//! Phase 0 defines the counters the engine reports and the verdict it returns.

pub mod compile;
pub mod engine;
pub mod eval;
pub mod host;
pub mod vars;

pub use compile::{
    CompileError, CompileFailure, CompileLimits, CompileReport, CompiledOption, CompiledRule,
    CompiledRuleset,
};
pub use engine::{AlertRecord, Engine, EngineCounters, EngineLimits};
pub use eval::{evaluate, Buffers, FlowBits, MatchInput, MatchOutcome};
pub use host::{evaluate_host, CompiledHostRule, HostObservation, HostRuleset};
pub use vars::{AddressSet, CompiledHeader, PortSet, VarError, VarTable};
