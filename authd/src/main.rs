use std::{path::PathBuf, sync::Arc};

use argh::FromArgs;
use authd::{
    rpc::{Authd, DefaultCipherSuite},
    types::{Group, Passwd, Shadow},
};
use rand::rngs::OsRng;
use tarpc::{
    server::{BaseChannel, Channel},
    tokio_serde::formats::Json,
};
use tokio::{net::TcpListener, task::JoinSet};
use tracing_subscriber::{
    fmt::format::FmtSpan, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

use opaque_ke::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerLogin, ServerLoginStartParameters,
    ServerRegistration, ServerSetup,
};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

struct SharedState {
    setup: ServerSetup<DefaultCipherSuite>,
    config: authd::Config,
}
impl SharedState {
    fn find_password_file(&self, username: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.config.opaque_cookies.join(username);
        Ok(std::fs::read(path)?)
    }
}

#[derive(Clone)]
struct AuthdSession {
    state: Arc<SharedState>,
    login_progress: Option<ServerLogin<DefaultCipherSuite>>,
    peer_addr: std::net::SocketAddr,
    authed_as: Option<String>,
    session_key: Option<Vec<u8>>,
}

#[tarpc::server]
impl Authd for AuthdSession {
    async fn get_all_groups(self, _ctx: tarpc::context::Context) -> Vec<Group> {
        vec![]
    }
    async fn get_group_by_name(self, _ctx: tarpc::context::Context, name: String) -> Option<Group> {
        None
    }
    async fn get_group_by_gid(self, _ctx: tarpc::context::Context, gid: u32) -> Option<Group> {
        None
    }

    async fn get_all_passwd(self, _ctx: tarpc::context::Context) -> Vec<Passwd> {
        vec![]
    }
    async fn get_passwd_by_name(
        self,
        _ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Passwd> {
        None
    }
    async fn get_passwd_by_uid(self, _ctx: tarpc::context::Context, uid: u32) -> Option<Passwd> {
        None
    }

    async fn get_all_shadow(self, _ctx: tarpc::context::Context) -> Vec<Shadow> {
        vec![]
    }
    async fn get_shadow_by_name(
        self,
        _ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Shadow> {
        None
    }

    async fn register_new_user(
        mut self,
        _ctx: tarpc::context::Context,
        username: String,
        selected_uid: Option<u32>,
        reg: RegistrationRequest<DefaultCipherSuite>,
    ) -> RegistrationResponse<DefaultCipherSuite> {
        /* TODO: do something with selected_id? run the autoallocate? */
        let reg = ServerRegistration::<DefaultCipherSuite>::start(
            &self.state.setup,
            reg,
            username.as_bytes(),
        )
        .unwrap();
        self.authed_as = Some(username);
        reg.message
    }

    async fn finish_registration(
        self,
        _ctx: tarpc::context::Context,
        reg: RegistrationUpload<DefaultCipherSuite>,
    ) {
        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(reg);
        let path = self
            .state
            .config
            .opaque_cookies
            .join(self.authed_as.unwrap());
        std::fs::write(path, password_file.serialize()).expect("writing out opaque cookie");
    }

    async fn start_login(
        mut self,
        _ctx: tarpc::context::Context,
        username: String,
        req: CredentialRequest<DefaultCipherSuite>,
    ) -> Result<CredentialResponse<DefaultCipherSuite>, String> {
        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(
            &self
                .state
                .find_password_file(&username)
                .expect("deserializing opaque cookie"),
        )
        .unwrap();
        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.state.setup,
            Some(password_file),
            req,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        self.login_progress = Some(server_login_start_result.state);
        Ok(server_login_start_result.message)
    }

    async fn finish_login(
        self,
        _ctx: tarpc::context::Context,
        req: CredentialFinalization<DefaultCipherSuite>,
    ) {
        let server_login = self.login_progress.expect("no login to finish");
        server_login.finish(req).expect("incorrect password");
    }
}

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command.
struct AuthdArgs {
    #[argh(option)]
    /// config file to load (or /etc/auth/authd.toml, $HOME/.local/share/authd.toml)
    config_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;

    let args: AuthdArgs = argh::from_env();

    let cfgdir = authd::find_config_dir()?;
    let config_path = args
        .config_file
        .unwrap_or_else(|| cfgdir.join("authd.toml"));

    let config_file: authd::Config = toml::from_slice(&std::fs::read(&config_path)?)?;

    let server_addrs = config_file.bind_addrs.clone();

    let tls_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                vec![Certificate(
                    std::fs::read(&config_file.cert).expect("read cert"),
                )],
                PrivateKey(std::fs::read(&config_file.key).expect("read key")),
            )?,
    );

    let state = Arc::new(SharedState {
        setup: ServerSetup::deserialize(&std::fs::read(&config_file.opaque_server_setup)?)
            .expect("deserializing opaque setup"),
        config: config_file.clone(),
    });

    let mut set = JoinSet::new();

    for bindaddr in server_addrs {
        let state = state.clone();
        let tls_config = tls_config.clone();
        let acceptor: TlsAcceptor = tls_config.into();

        let listener = TcpListener::bind(&bindaddr).await.expect("tcp bind");

        set.spawn(async move {
            loop {
                let acceptor = acceptor.clone();
                let state = state.clone();
                let (stream, peer_addr) = listener.accept().await.expect("tcp accept");

                tokio::spawn(async move {
                    let stream = acceptor.accept(stream).await.expect("accepting tls");
                    let tport = tarpc::serde_transport::Transport::from((stream, Json::default()));
                    let channel = BaseChannel::with_defaults(tport);

                    let session = AuthdSession {
                        state: state.clone(),
                        peer_addr,
                        authed_as: None,
                        session_key: None,
                        login_progress: None,
                    };
                    channel.execute(session.serve()).await;
                });
            }
        });
    }

    while !set.is_empty() {
        set.join_next().await;
    }

    Ok(())
}
