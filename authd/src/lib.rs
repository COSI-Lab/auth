use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use tokio_rustls::TlsConnector;

use stubborn_io::{ReconnectOptions, StubbornTcpStream};
use tarpc::serde_transport::Transport;
use tokio::net::ToSocketAddrs;

pub mod rpc;
pub mod types;

#[derive(serde::Deserialize, Clone)]
pub struct AuthdConfig {
    pub bind_addrs: Vec<SocketAddr>,
    pub opaque_server_setup: String,
    pub authoritative_name: String,
    pub passwd_file: String,
    pub shadow_file: String,
    pub opaque_cookies: String,
    pub cert: String,
    pub key: String,
}

impl AuthdConfig {
    /// Shell-expand any paths in the config.
    pub fn expand(&mut self) {
        self.opaque_server_setup = shellexpand::full(&self.opaque_server_setup)
            .expect("expanding opaque_server_setup")
            .into_owned()
            .into();
        self.passwd_file = shellexpand::full(&self.passwd_file)
            .expect("expanding passwd_file")
            .into_owned()
            .into();
        self.shadow_file = shellexpand::full(&self.shadow_file)
            .expect("expanding shadow_file")
            .into_owned()
            .into();
        self.opaque_cookies = shellexpand::full(&self.opaque_cookies)
            .expect("expanding opaque_cookies")
            .into_owned()
            .into();
        self.cert = shellexpand::full(&self.cert)
            .expect("expanding cert")
            .into_owned()
            .into();
        self.key = shellexpand::full(&self.key)
            .expect("expanding key")
            .into_owned()
            .into();
    }
}

/// Find the first of `/etc/auth` or `$XDG_CONFIG_DIR/auth` that exists.
/// 
/// If neither exist, return `$XDG_CONFIG_DIR/auth`. Unless `$XDG_CONFIG_DIR` is bogus, in which
/// case `Err`.
pub fn find_config_dir() -> anyhow::Result<PathBuf> {
    if let Ok(true) = std::path::Path::new("/etc/auth").try_exists() {
        return Ok("/etc/auth".into());
    }
    let mut config_dir = dirs_next::config_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not find config directory",
        )
    })?;
    config_dir.push("auth");
    Ok(config_dir)
}

/// Connect to authd over TLS, already knowing + trusting its certificate (if we don't get MITM).
/// 
/// The server_name is used for SNI. Setting it to localhost is fine for testing.
pub async fn client_connect<A: ToSocketAddrs + Unpin + Clone + Send + Sync + 'static>(
    addr: A,
    cert: &rustls::Certificate,
    server_name: &str,
) -> anyhow::Result<rpc::AuthdClient> {
    let reconnect_opts = ReconnectOptions::new()
        .with_exit_if_first_connect_fails(false)
        .with_retries_generator(|| std::iter::repeat(Duration::from_secs(1)));
    let tcp_stream = StubbornTcpStream::connect_with_options(addr, reconnect_opts).await?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let servername = rustls::ServerName::try_from(server_name).unwrap();
    let transport = Transport::from((
        connector.connect(servername, tcp_stream).await?,
        tarpc::tokio_serde::formats::Json::default(),
    ));
    Ok(rpc::AuthdClient::new(tarpc::client::Config::default(), transport).spawn())
}
