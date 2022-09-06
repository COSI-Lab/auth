#[tokio::main]
async fn main() -> anyhow::Result<()> {
    authd::rpc::main().await
}
