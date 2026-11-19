use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Nexo 联巢独立节点")]
struct Cli {
    #[arg(long, default_value = "./data/nexo", global = true)]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动节点；首次接入从标准输入读取一次性凭证。
    Node {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        enroll: bool,
        #[arg(long)]
        enroll_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%Y-%m-%d %H:%M:%S%.3f %:z".into(),
        ))
        .with_target(false)
        .compact()
        .init();
    let cli = Cli::parse();
    let Command::Node {
        server_url,
        enroll,
        enroll_only,
    } = cli.command;
    nexo_node::run(
        nexo_core::config::absolute(&cli.data_dir)?,
        server_url,
        enroll || enroll_only,
        enroll_only,
    )
    .await
}
