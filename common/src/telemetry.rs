use std::env;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

pub fn init_tracing<Sink>(sink: Sink)
where
    Sink: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter = EnvFilter::from_default_env();
    let log_format = env::var("LOG_FORMAT").unwrap_or_else(|_| "human".to_string());

    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(sink)
        .with_target(false);

    match log_format.as_str() {
        "compact" => builder.with_ansi(false).compact().init(),
        "json" => builder.json().init(),
        _ => builder.init(),
    }
}
