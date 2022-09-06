use crate::types::{Group, Passwd, Shadow};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = argon2::Argon2<'static>;
}

#[derive(Deserialize, Serialize, Debug)]
pub enum RpcError {
    NotAuthorized,
    AuthenticationFailure,
}

#[tarpc::service]
pub trait Authd {
    async fn get_all_groups() -> Vec<Group>;
    async fn get_group_by_name(name: String) -> Option<Group>;
    async fn get_group_by_gid(gid: u32) -> Option<Group>;

    async fn get_all_passwd() -> Vec<Passwd>;
    async fn get_passwd_by_name(name: String) -> Option<Passwd>;
    async fn get_passwd_by_uid(uid: u32) -> Option<Passwd>;

    async fn get_all_shadow() -> Vec<Shadow>;
    async fn get_shadow_by_name(name: String) -> Option<Shadow>;

    async fn start_login(
        username: String,
        req: CredentialRequest<DefaultCipherSuite>,
    ) -> Result<CredentialResponse<DefaultCipherSuite>, RpcError>;
    async fn finish_login(req: CredentialFinalization<DefaultCipherSuite>);

    async fn register_new_user(
        username: String,
        selected_uid: Option<u32>,
        reg: RegistrationRequest<DefaultCipherSuite>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, RpcError>;
    async fn finish_registration(
        reg: RegistrationUpload<DefaultCipherSuite>,
    ) -> Result<(), RpcError>;
}

struct SharedState {
    setup: ServerSetup<DefaultCipherSuite>,
    config: crate::AuthdConfig,
}
impl SharedState {
    fn find_password_file(&self, username: &str) -> anyhow::Result<Vec<u8>> {
        let path = PathBuf::from(&self.config.opaque_cookies).join(username);
        Ok(std::fs::read(path)?)
    }

    async fn get_all_groups(&self) -> Vec<Group> {
        vec![Group {
            name: "auth-admins".into(),
            gid: 666,
            members: vec!["ember".into()],
        }]
    }

    async fn get_group_by_name(&self, name: &str) -> Option<Group> {
        let mut groups = self.get_all_groups().await;
        groups.retain(|g| g.name == name);
        groups.pop()
    }
}

struct AuthdSession {
    state: Arc<SharedState>,
    login_progress: Option<ServerLogin<DefaultCipherSuite>>,
    peer_addr: std::net::SocketAddr,
    authed_as: Option<String>,
    session_key: Option<Zeroizing<Vec<u8>>>,
}

impl AuthdSession {
    async fn auth_admin(&self) -> bool {
        if let Some(uname) = &self.authed_as {
            if self.session_key.is_some() {
                if let Some(admin) = self.state.get_group_by_name("auth-admins".into()).await {
                    if admin.members.contains(&uname) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[tarpc::server]
impl Authd for Arc<Mutex<AuthdSession>> {
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
        self,
        _ctx: tarpc::context::Context,
        username: String,
        selected_uid: Option<u32>,
        reg: RegistrationRequest<DefaultCipherSuite>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, RpcError> {
        let mut slf = self.lock().await;
        if !slf.auth_admin().await {
            return Err(RpcError::NotAuthorized);
        }
        /* TODO: do something with selected_id? run the autoallocate? */
        let reg = ServerRegistration::<DefaultCipherSuite>::start(
            &slf.state.setup,
            reg,
            username.as_bytes(),
        )
        .unwrap();
        slf.authed_as = Some(username);
        Ok(reg.message)
    }

    async fn finish_registration(
        self,
        _ctx: tarpc::context::Context,
        reg: RegistrationUpload<DefaultCipherSuite>,
    ) -> Result<(), RpcError> {
        let slf = self.lock().await;
        if !slf.auth_admin().await {
            return Err(RpcError::NotAuthorized);
        }

        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(reg);
        let path =
            PathBuf::from(&slf.state.config.opaque_cookies).join(slf.authed_as.as_ref().unwrap());
        std::fs::write(path, password_file.serialize()).expect("writing out opaque cookie");
        Ok(())
    }

    async fn start_login(
        self,
        _ctx: tarpc::context::Context,
        username: String,
        req: CredentialRequest<DefaultCipherSuite>,
    ) -> Result<CredentialResponse<DefaultCipherSuite>, RpcError> {
        let mut slf = self.lock().await;

        let password_file = slf.state.find_password_file(&username).ok().and_then(|d| {
            ServerRegistration::<DefaultCipherSuite>::deserialize(&d)
                .map_err(|e| eprintln!("error deserializing password file: {:?}", e))
                .ok()
        });

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &slf.state.setup,
            password_file,
            req,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        slf.login_progress = Some(server_login_start_result.state);
        slf.authed_as = Some(username);
        Ok(server_login_start_result.message)
    }

    async fn finish_login(
        self,
        _ctx: tarpc::context::Context,
        req: CredentialFinalization<DefaultCipherSuite>,
    ) {
        let mut slf = self.lock().await;

        let server_login = slf.login_progress.take().expect("no login to finish");
        let finish_result = server_login.finish(req).expect("incorrect password");
        slf.session_key = Some(Zeroizing::new(finish_result.session_key.to_vec()));
    }
}

use argh::FromArgs;
use tarpc::{
    server::{BaseChannel, Channel},
    tokio_serde::formats::Json,
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinSet};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::{
    fmt::format::FmtSpan, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command.
struct AuthdArgs {
    #[argh(option)]
    /// config file to load (or /etc/auth/authd.toml, $HOME/.local/share/authd.toml)
    config_file: Option<PathBuf>,
}

// this is here so the stuff above doesn't need to be pub or pub(crate)
// ugh rust is really lots of typing sometimes

pub async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;

    let args: AuthdArgs = argh::from_env();

    let cfgdir = crate::find_config_dir()?;
    let config_path = args
        .config_file
        .unwrap_or_else(|| cfgdir.join("authd.toml"));

    let mut config_file: crate::AuthdConfig = toml::from_slice(&std::fs::read(&config_path)?)?;
    config_file.expand();
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
        setup: opaque_ke::ServerSetup::deserialize(
            &std::fs::read(&config_file.opaque_server_setup).expect("read opaque"),
        )
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

                    let session = Arc::new(Mutex::new(AuthdSession {
                        state: state.clone(),
                        peer_addr,
                        authed_as: None,
                        session_key: None,
                        login_progress: None,
                    }));
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
