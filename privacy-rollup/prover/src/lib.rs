//! Proving library of the privacy rollup: the user-side zero-knowledge join-split receipt and the
//! operator-side settlement receipt. The `joinsplit` and `settle` binaries, the SDK and the batcher
//! are thin wrappers around it.
pub mod settle;
pub mod user;

pub use pr_methods::{APPLY_BATCH_ID, JOINSPLIT_ID};

/// Wall-clock stopwatch for stage timings.
pub(crate) struct Clock(std::time::Instant);

impl Clock {
    pub(crate) fn start() -> Clock {
        Clock(std::time::Instant::now())
    }

    pub(crate) fn seconds(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}
