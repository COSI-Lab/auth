use authd::{
    rpc::Authd,
    types::{Group, Passwd, Shadow},
};
use futures_util::{future, StreamExt};
use tarpc::{
    server::{incoming::Incoming, Channel},
    tokio_serde::formats::Json,
};
use tracing_subscriber::{
    fmt::format::FmtSpan, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

#[derive(Clone)]
struct FauxDb(std::net::SocketAddr);

#[tarpc::server]
impl Authd for FauxDb {
    async fn get_all_groups(self, ctx: tarpc::context::Context) -> Vec<Group> {
        vec![]
    }
    async fn get_group_by_name(self, ctx: tarpc::context::Context, name: String) -> Option<Group> {
        None
    }
    async fn get_group_by_gid(self, ctx: tarpc::context::Context, gid: u32) -> Option<Group> {
        None
    }

    async fn get_all_passwd(self, ctx: tarpc::context::Context) -> Vec<Passwd> {
        vec![]
    }
    async fn get_passwd_by_name(
        self,
        ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Passwd> {
        None
    }
    async fn get_passwd_by_uid(self, ctx: tarpc::context::Context, uid: u32) -> Option<Passwd> {
        None
    }

    async fn get_all_shadow(self, ctx: tarpc::context::Context) -> Vec<Shadow> {
        vec![]
    }
    async fn get_shadow_by_name(
        self,
        ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Shadow> {
        None
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_addr = ("127.0.0.1", 8080);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;

    // tarpc example service boilerplate
    let mut listener = tarpc::serde_transport::tcp::listen(&server_addr, Json::default).await?;
    listener.config_mut().max_frame_length(usize::MAX);
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(tarpc::server::BaseChannel::with_defaults)
        // Limit channels to 10 per IP (VM hosts contain many endpoints, maybe they all log in at the same time).
        .max_channels_per_key(10, |t| t.transport().peer_addr().unwrap().ip())
        .map(|channel| {
            let server = FauxDb(channel.transport().peer_addr().unwrap());
            channel.execute(server.serve())
        })
        // Max 100 channels (ITL + COSI + Servers + VMs should be fine? )
        .buffer_unordered(100)
        .for_each(|_| async {})
        .await;

    Ok(())
}
