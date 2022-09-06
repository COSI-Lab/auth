use std::{net::SocketAddr, path::PathBuf};

pub mod rpc;
pub mod types;

#[derive(serde::Deserialize,Clone)]
pub struct Config {
    pub bind_addrs: Vec<SocketAddr>,
    pub opaque_server_setup: PathBuf,
    pub authoritative_name: String,
    pub passwd_file: PathBuf,
    pub shadow_file: PathBuf,
    pub opaque_cookies: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub fn find_config_dir() -> std::io::Result<PathBuf> {
    if let Ok(true) = std::path::Path::new("/etc/auth").try_exists() {
        return Ok("/etc/auth".into());
    }
    let mut config_dir = dirs::config_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not find config directory",
        )
    })?;
    config_dir.push("auth");
    Ok(config_dir)
}
