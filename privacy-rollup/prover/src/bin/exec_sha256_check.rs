//! Execute a bounded diagnostic guest and compare every journal byte with the
//! native registry-SHA reference. Optional frames also allow fixed-proof checks.
use risc0_zkvm::{default_executor, ExecutorEnv};
use tracing::{span, Event, Id, Metadata, Subscriber};

struct InfoEvents;
impl Subscriber for InfoEvents {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
                use core::fmt::Write;
                let _ = write!(&mut self.0, "{}={value:?} ", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        eprintln!("{}", fields.0);
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() >= 3, "usage: exec_sha256_check <combined-guest.bin> <expected-journal.bin> [frames..]");
    let program = std::fs::read(&args[1])?;
    let expected = std::fs::read(&args[2])?;
    std::env::set_var("RISC0_INFO", "1");
    tracing::subscriber::set_global_default(InfoEvents)?;
    let mut builder = ExecutorEnv::builder();
    builder.session_limit(Some(2_000_000_000));
    for frame in &args[3..] {
        builder.write_frame(&std::fs::read(frame)?);
    }
    let start = std::time::Instant::now();
    let info = default_executor().execute(builder.build()?, &program)?;
    anyhow::ensure!(info.journal.bytes == expected, "guest journal differs from reference");
    println!(
        "{}",
        serde_json::json!({"execution_only":true,"matched_bytes":expected.len(),"cycles":info.cycles(),"segments":info.segments.len(),"runtime_seconds":start.elapsed().as_secs_f64()})
    );
    Ok(())
}
