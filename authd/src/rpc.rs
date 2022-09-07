//! RPC server exposing all of the functionality over JSON over TLS.

use crate::{
    files::Files,
    types::{Group, Passwd, Shadow},
};
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
    type Ksf = opaque_ke::ksf::Identity;
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

/// All of the shared state amongst all of the various open sessions.
///
/// Ideally the DB context access lives here.
struct SharedState {
    setup: ServerSetup<DefaultCipherSuite>,
    config: crate::AuthdConfig,
    files: Files,
}
impl std::fmt::Debug for SharedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedState").finish()
    }
}
impl SharedState {
    fn find_password_file(&self, username: &str) -> anyhow::Result<Vec<u8>> {
        let path = PathBuf::from(&self.config.opaque_cookies).join(username);
        Ok(std::fs::read(path)?)
    }
}

#[derive(Debug)]
/// A single open connection to authd.
struct AuthdSession {
    state: Arc<Mutex<SharedState>>,
    /// Stores the interim state of the 3-step login protocol.
    login_progress: Option<ServerLogin<DefaultCipherSuite>>,
    /// Who are we talking to?
    _peer_addr: std::net::SocketAddr,
    /// They have claimed to have this username
    purported_username: Option<String>,
    /// If this is Some, purported_username is authenticated.
    session_key: Option<Zeroizing<Vec<u8>>>,
}

impl AuthdSession {
    async fn auth_admin(&self) -> bool {
        if let Some(uname) = &self.purported_username {
            if self.session_key.is_some() {
                if let Some(admin) = self
                    .state
                    .lock()
                    .await
                    .files
                    .group
                    .data
                    .iter()
                    .find(|x| x.name == "auth-admins")
                {
                    if admin.members.contains(uname) {
                        tracing::info!("{} just did admin things", uname);
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
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files.group.data.clone()
    }

    async fn get_group_by_name(self, _ctx: tarpc::context::Context, name: String) -> Option<Group> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files
            .group
            .data
            .iter()
            .find(|x| x.name == name)
            .cloned()
    }
    async fn get_group_by_gid(self, _ctx: tarpc::context::Context, gid: u32) -> Option<Group> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files.group.data.iter().find(|x| x.gid == gid).cloned()
    }

    async fn get_all_passwd(self, _ctx: tarpc::context::Context) -> Vec<Passwd> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files.passwd.data.clone()
    }

    async fn get_passwd_by_name(
        self,
        _ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Passwd> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files
            .passwd
            .data
            .iter()
            .find(|x| x.name == name)
            .cloned()
    }

    async fn get_passwd_by_uid(self, _ctx: tarpc::context::Context, uid: u32) -> Option<Passwd> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files.passwd.data.iter().find(|x| x.id == uid).cloned()
    }

    async fn get_all_shadow(self, _ctx: tarpc::context::Context) -> Vec<Shadow> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files.shadow.data.clone()
    }

    async fn get_shadow_by_name(
        self,
        _ctx: tarpc::context::Context,
        name: String,
    ) -> Option<Shadow> {
        let slf = self.lock().await;
        let mut slf = slf.state.lock().await;
        slf.files.refresh().expect("refreshing fio");
        slf.files
            .shadow
            .data
            .iter()
            .find(|x| x.name == name)
            .cloned()
    }

    async fn register_new_user(
        self,
        _ctx: tarpc::context::Context,
        username: String,
        _selected_uid: Option<u32>,
        reg: RegistrationRequest<DefaultCipherSuite>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, RpcError> {
        let mut slf = self.lock().await;
        if !slf.auth_admin().await {
            return Err(RpcError::NotAuthorized);
        }
        /* TODO: do something with selected_id? run the autoallocate? */
        let reg = ServerRegistration::<DefaultCipherSuite>::start(
            &slf.state.lock().await.setup,
            reg,
            username.as_bytes(),
        )
        .unwrap();
        slf.purported_username = Some(username);
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
        let path = PathBuf::from(&slf.state.lock().await.config.opaque_cookies)
            .join(slf.purported_username.as_ref().unwrap());
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

        let password_file = slf
            .state
            .lock()
            .await
            .find_password_file(&username)
            .ok()
            .and_then(|d| {
                ServerRegistration::<DefaultCipherSuite>::deserialize(&d)
                    .map_err(|e| eprintln!("error deserializing password file: {:?}", e))
                    .ok()
            });

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &slf.state.lock().await.setup,
            password_file,
            req,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        slf.login_progress = Some(server_login_start_result.state);
        slf.purported_username = Some(username);
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
/// authentication daemon
struct AuthdArgs {
    #[argh(option)]
    /// config file to load (or /etc/auth/authd.toml, $HOME/.config/auth/authd.toml)
    config_file: Option<PathBuf>,
}

// this is here so the stuff above doesn't need to be pub or pub(crate)
// ugh rust is really lots of typing sometimes

pub async fn main() -> anyhow::Result<()> {
    // pretty logs if you set RUST_LOG
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

    let state = Arc::new(Mutex::new(SharedState {
        setup: opaque_ke::ServerSetup::deserialize(
            &std::fs::read(&config_file.opaque_server_setup).expect("read opaque"),
        )
        .expect("deserializing opaque setup"),
        config: config_file.clone(),
        files: Files::new(
            config_file.passwd_file,
            config_file.group_file,
            config_file.shadow_file,
        ),
    }));

    let mut set = JoinSet::new();

    for bindaddr in server_addrs {
        let state = state.clone();
        let tls_config = tls_config.clone();
        let acceptor: TlsAcceptor = tls_config.into();

        let listener = TcpListener::bind(&bindaddr).await.expect("tcp bind");

        set.spawn(async move {
            tracing::info!("listening on {}", bindaddr);
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
                        _peer_addr: peer_addr,
                        purported_username: None,
                        session_key: None,
                        login_progress: None,
                    }));
                    tracing::info!("new connection: {:?}", session);
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
