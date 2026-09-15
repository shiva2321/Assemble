pub mod assembler;
pub mod cli;
pub mod emulator;
pub mod fixer;
pub mod knowledge;
pub mod linter;
pub mod mcp;
pub mod safety;
pub mod templates;
pub mod types;
pub mod util;
pub mod verifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cli::run_cli().await
}
