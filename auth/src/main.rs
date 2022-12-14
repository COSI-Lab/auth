use argh::FromArgs;
use authd::{rpc::DefaultCipherSuite, SocketName};
use chrono::Datelike;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientRegistrationFinishParameters};
use std::{io::Write, net::ToSocketAddrs, path::PathBuf};
use tarpc::context;
use zeroize::Zeroizing;

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command.
struct TopLevel {
    #[argh(subcommand)]
    nested: AuthSubcommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum AuthSubcommands {
    GenOpaque(GenOpaque),
    CreateUser(CreateUser),
    BootstrapUser(LetThereBeAdmin),
    LocalCreateUser(LocalCreateUser),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Generate OPAQUE private key for the server
#[argh(subcommand, name = "generate-opaque-secret")]
struct GenOpaque {
    #[argh(option)]
    /// where to write the file
    output: PathBuf,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Create a new user
#[argh(subcommand, name = "create-user")]
struct CreateUser {
    #[argh(option)]
    /// username
    name: String,
    #[argh(option)]
    /// uid
    uid: u32,
    #[argh(option)]
    /// name of shell to use
    shell: String,
    #[argh(option)]
    /// path to home directory
    homedir: String,
    #[argh(option)]
    /// authd IP address and port
    host: SocketName,
    #[argh(option)]
    /// server identity certificate
    cert: PathBuf,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Create a new user in the local files
#[argh(subcommand, name = "local-create-user")]
struct LocalCreateUser {
    #[argh(option)]
    /// username
    name: String,
    #[argh(option)]
    /// name of shell to use
    authd_config: PathBuf,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Bootstrap the first admin user
#[argh(subcommand, name = "bootstrap-admin")]
struct LetThereBeAdmin {
    #[argh(option)]
    /// username
    name: String,
    #[argh(option)]
    /// uid
    uid: u32,
    #[argh(option)]
    /// server config to be bootstrapping for
    authd_config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args: TopLevel = argh::from_env();

    match args.nested {
        AuthSubcommands::GenOpaque(geno) => {
            let mut rng = opaque_ke::rand::rngs::OsRng;
            let setup = opaque_ke::ServerSetup::<authd::rpc::DefaultCipherSuite>::new(&mut rng);
            std::fs::write(geno.output, &setup.serialize()).expect("writing opaque server setup")
        }
        AuthSubcommands::CreateUser(cuser) => {
            let mut rng = opaque_ke::rand::rngs::OsRng;

            let cert = rustls::Certificate(std::fs::read(cuser.cert).expect("reading cert"));

            let cl = authd::client_connect(
                cuser
                    .host
                    .to_socket_addrs()
                    .expect("resolving")
                    .into_iter()
                    .next()
                    .expect("need a host"),
                &cert,
                "localhost",
            )
            .await
            .expect("connecting to authd");

            let admin_user = rpassword::prompt_password("admin username: ").unwrap();
            let admin_pass = rpassword::prompt_password("admin password: ")
                .unwrap()
                .into_bytes();

            let login = ClientLogin::<DefaultCipherSuite>::start(&mut rng, &admin_pass)
                .expect("starting admin login");
            let login_req = cl
                .start_login(context::current(), admin_user.clone(), login.message)
                .await?
                .expect("could not start admin login");
            let finished = login
                .state
                .finish(
                    &admin_pass,
                    login_req,
                    ClientLoginFinishParameters::default(),
                )
                .expect("admin login failure: bad password?");
            cl.finish_login(context::current(), finished.message)
                .await
                .expect("could not finish admin login");

            println!("welcome back to authd, {}", admin_user);
            let pwbytes = loop {
                let pwbytes = Zeroizing::new(
                    rpassword::prompt_password("New OPAQUE password:")
                        .expect("reading pw1")
                        .into_bytes(),
                );
                let pwbytes2 = Zeroizing::new(
                    rpassword::prompt_password("Confirm new OPAQUE password:")
                        .expect("reading pw2")
                        .into_bytes(),
                );
                if pwbytes == pwbytes2 {
                    break pwbytes;
                } else {
                    eprintln!("Passwords don't match, try again");
                }
            };
            fn generous() -> tarpc::context::Context {
                let mut ctx = tarpc::context::current();
                ctx.deadline = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
                ctx
            }

            let reg =
                opaque_ke::ClientRegistration::<DefaultCipherSuite>::start(&mut rng, &pwbytes)
                    .expect("starting registration");
            let reg_resp = cl
                .register_new_user(generous(), cuser.name.clone(), Some(cuser.uid), reg.message)
                .await?
                .expect("could not register user");

            let completed_reg = reg
                .state
                .finish(
                    &mut rng,
                    &pwbytes,
                    reg_resp,
                    ClientRegistrationFinishParameters::default(),
                )
                .expect("finishing registration");
            cl.finish_registration(generous(), completed_reg.message)
                .await?
                .expect("could not finish registration");
            println!("registered new user {}!", cuser.name);
        }
        AuthSubcommands::BootstrapUser(prime_mover) => {
            let mut cfg: authd::AuthdConfig =
                toml::from_slice(&std::fs::read(&prime_mover.authd_config)?)?;
            cfg.expand();
            let mut rng = opaque_ke::rand::rngs::OsRng;
            let srv = opaque_ke::ServerSetup::<DefaultCipherSuite>::deserialize(&std::fs::read(
                cfg.opaque_server_setup,
            )?)
            .expect("reading opaque server setup");
            let pwbytes = loop {
                let pwbytes = Zeroizing::new(
                    rpassword::prompt_password("New OPAQUE password:")
                        .expect("reading pw1")
                        .into_bytes(),
                );
                let pwbytes2 = Zeroizing::new(
                    rpassword::prompt_password("Confirm new OPAQUE password:")
                        .expect("reading pw2")
                        .into_bytes(),
                );
                if pwbytes == pwbytes2 {
                    break pwbytes;
                } else {
                    eprintln!("Passwords don't match, try again");
                }
            };
            let client_reg =
                opaque_ke::ClientRegistration::<DefaultCipherSuite>::start(&mut rng, &pwbytes)
                    .expect("starting registration");

            let server_reg = opaque_ke::ServerRegistration::<DefaultCipherSuite>::start(
                &srv,
                client_reg.message,
                prime_mover.name.as_bytes(),
            )
            .unwrap();
            let completed_reg = client_reg
                .state
                .finish(
                    &mut rng,
                    &pwbytes,
                    server_reg.message,
                    ClientRegistrationFinishParameters::default(),
                )
                .expect("finishing registration");

            let password_file =
                opaque_ke::ServerRegistration::<DefaultCipherSuite>::finish(completed_reg.message);
            let path = PathBuf::from(&cfg.opaque_cookies).join(prime_mover.name.clone());
            std::fs::write(path, password_file.serialize()).expect("writing out opaque cookie");

            println!("welcome to the matrix, {}", prime_mover.name);

            // TODO: add user to auth-admins
        }

        AuthSubcommands::LocalCreateUser(luser) => {
            let mut cfg: authd::AuthdConfig =
                toml::from_slice(&std::fs::read(&luser.authd_config)?)?;
            cfg.expand();

            let pwbytes = loop {
                let pwbytes = Zeroizing::new(
                    rpassword::prompt_password(format!("New password for {}:", luser.name))
                        .expect("reading pw1")
                        .into_bytes(),
                );
                let pwbytes2 = Zeroizing::new(
                    rpassword::prompt_password("Confirm new password:")
                        .expect("reading pw2")
                        .into_bytes(),
                );
                if pwbytes == pwbytes2 {
                    break pwbytes;
                } else {
                    eprintln!("Passwords don't match, try again");
                }
            };
            let hash = pwhash::bcrypt::hash_with(
                pwhash::bcrypt::BcryptSetup {
                    variant: Some(pwhash::bcrypt::BcryptVariant::V2y),
                    cost: Some(12),
                    ..Default::default()
                },
                &pwbytes,
            )
            .expect("bcrypt failed");

            let files =
                authd::files::Files::new(&cfg.passwd_file, &cfg.group_file, &cfg.shadow_file);
            let all_users = files.get_all_passwd()?;
            let largest_uid = all_users
                .iter()
                .max_by_key(|u| u.id)
                .map(|p| p.id)
                .unwrap_or(1);
            let mut f = std::fs::File::options()
                .write(true)
                .create(true)
                .open(PathBuf::from(&cfg.passwd_file))?;

            std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0))?;
            writeln!(
                f,
                "{}",
                authd::types::Passwd {
                    name: luser.name.clone(),
                    id: largest_uid + 1,
                    gecos: "freshly made by auth".into(),
                    dir: "/nonexistent".into(),
                    shell: "/bin/false".into(),
                }
            )?;
            let mut f = std::fs::File::options()
                .write(true)
                .create(true)
                .open(PathBuf::from(&cfg.shadow_file))?;

            std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0))?;
            let today_days = chrono::Utc::today().num_days_from_ce()
                - chrono::NaiveDate::from_ymd(1970, 1, 1).num_days_from_ce();
            writeln!(
                f,
                "{}",
                authd::types::Shadow {
                    name: luser.name.clone(),
                    passwd: hash,
                    last_change: today_days as _,
                    change_min_days: 0,
                    change_max_days: 0,
                    change_warn_days: 0,
                    change_inactive_days: None,
                    expire_date: None,
                }
            )?;

            let mut rng = opaque_ke::rand::rngs::OsRng;
            let srv = opaque_ke::ServerSetup::<DefaultCipherSuite>::deserialize(&std::fs::read(
                cfg.opaque_server_setup,
            )?)
            .expect("reading opaque server setup");
            let client_reg =
                opaque_ke::ClientRegistration::<DefaultCipherSuite>::start(&mut rng, &pwbytes)
                    .expect("starting registration");

            let server_reg = opaque_ke::ServerRegistration::<DefaultCipherSuite>::start(
                &srv,
                client_reg.message,
                luser.name.as_bytes(),
            )
            .unwrap();
            let completed_reg = client_reg
                .state
                .finish(
                    &mut rng,
                    &pwbytes,
                    server_reg.message,
                    ClientRegistrationFinishParameters::default(),
                )
                .expect("finishing registration");

            let password_file =
                opaque_ke::ServerRegistration::<DefaultCipherSuite>::finish(completed_reg.message);
            let path = PathBuf::from(&cfg.opaque_cookies).join(luser.name.clone());
            std::fs::write(path, password_file.serialize()).expect("writing out opaque cookie");
        }
    }

    Ok(())
}
