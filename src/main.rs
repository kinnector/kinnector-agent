#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    antitheft_agent::run_agent().await
}
