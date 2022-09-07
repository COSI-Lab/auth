use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use tokio_rustls::TlsConnector;

use stubborn_io::{ReconnectOptions, StubbornTcpStream};
use tarpc::serde_transport::Transport;
use tokio::net::ToSocketAddrs;

pub mod files;
pub mod rpc;
pub mod types;

#[derive(Debug, PartialEq, Eq)]
pub enum SocketName {
    Dns(String, u16),
    Addr(SocketAddr),
}

impl FromStr for SocketName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match SocketAddr::from_str(s) {
            Ok(sa) => Ok(SocketName::Addr(sa)),
            Err(_) => {
                if s.contains(':') {
                    let mut comps = s.split(':');
                    let (l, r) = (comps.next().unwrap(), comps.next().unwrap());
                    Ok(SocketName::Dns(
                        l.into(),
                        u16::from_str(r).map_err(|e| anyhow::anyhow!(e.to_string()))?,
                    ))
                } else {
                    Err(anyhow::anyhow!("not a socket addr & missing port for dns, example: auth.cosi.clarkson.edu:8765"))
                }
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for SocketName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        SocketName::from_str(&s).map_err(|e| D::Error::custom(e.to_string()))
    }
}

impl std::net::ToSocketAddrs for SocketName {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        Ok(match self {
            SocketName::Dns(host, port) => (host.as_str(), *port)
                .to_socket_addrs()?
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter(),
            SocketName::Addr(sa) => vec![*sa].into_iter(),
        })
    }
}
#[derive(Debug, serde::Deserialize, Clone)]
pub struct AuthdConfig {
    pub bind_addrs: Vec<SocketAddr>,
    pub opaque_server_setup: String,
    pub authoritative_name: String,
    pub passwd_file: String,
    pub shadow_file: String,
    pub group_file: String,
    pub opaque_cookies: String,
    pub cert: String,
    pub key: String,
}

impl AuthdConfig {
    /// Shell-expand any paths in the config.
    pub fn expand(&mut self) {
        self.opaque_server_setup = shellexpand::full(&self.opaque_server_setup)
            .expect("expanding opaque_server_setup")
            .into();
        self.passwd_file = shellexpand::full(&self.passwd_file)
            .expect("expanding passwd_file")
            .into();
        self.shadow_file = shellexpand::full(&self.shadow_file)
            .expect("expanding shadow_file")
            .into();
        self.group_file = shellexpand::full(&self.group_file)
            .expect("expanding group_file")
            .into();
        self.opaque_cookies = shellexpand::full(&self.opaque_cookies)
            .expect("expanding opaque_cookies")
            .into();
        self.cert = shellexpand::full(&self.cert)
            .expect("expanding cert")
            .into();
        self.key = shellexpand::full(&self.key).expect("expanding key").into();
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
