use authd::types::ToNSS;
use futures::executor::block_on;
use libc::c_int;
use libnss::group::{CGroup, Group, GroupHooks};
use libnss::interop::{Iterator, Response};
use libnss::passwd::{CPasswd, Passwd};
use std::ffi::CStr;
use std::net::ToSocketAddrs;
use std::str;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tarpc::context;
use tokio::runtime::Runtime;
use tokio::time::sleep_until;

#[derive(Default)]
struct ClientAccessControl {
    client: Arc<Mutex<Option<authd::rpc::AuthdClient>>>,
    latest_ts: Arc<Mutex<Option<Instant>>>,
}

#[derive(serde::Deserialize)]
struct NssConfig {
    host: authd::SocketName,
    cert: String,
}

impl ClientAccessControl {
    fn with_client<O>(&mut self, f: impl FnOnce(&mut authd::rpc::AuthdClient) -> O) -> O {
        let _guard = RT.enter();
        let mut lts = self.latest_ts.lock().unwrap();
        *lts = Some(std::time::Instant::now() + Duration::from_secs(30));
        let cl = self.client.clone();
        let latest_ts = self.latest_ts.clone();
        tokio::spawn(async move {
            loop {
                let dur = latest_ts.lock().unwrap().unwrap_or(Instant::now()).into();
                sleep_until(dur).await;
                // make sure it wasn't moved forward while we were sleeping
                if latest_ts.lock().unwrap().unwrap_or(Instant::now()) < Instant::now() {
                    *cl.lock().unwrap() = None;
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "nss_cosiauthd: ClientAccessControl: client timed out, closing connection."
                    );
                    break;
                }
            }
        });

        let mut client = self.client.lock().unwrap();
        if client.is_none() {
            *client = Some(
                block_on(authd::client_connect(
                    CFG.host
                        .to_socket_addrs()
                        .expect("resolving host")
                        .into_iter()
                        .next()
                        .expect("no host found"),
                    &rustls::Certificate(std::fs::read(&CFG.cert).expect("reading cert")),
                    "localhost",
                ))
                .unwrap(),
            );
        }
        f(client.as_mut().unwrap())
    }
}

lazy_static::lazy_static! {
    static ref PASSWD_ITERATOR: Mutex<Iterator<Passwd>> = Mutex::new(Iterator::<Passwd>::new());
    static ref GROUP_ITERATOR: Mutex<Iterator<Group>> = Mutex::new(Iterator::<Group>::new());
    static ref SHADOW_ITERATOR: Mutex<Iterator<libnss::shadow::Shadow>> = Mutex::new(Iterator::<libnss::shadow::Shadow>::new());

    static ref RPC: Mutex<ClientAccessControl> = Mutex::new(ClientAccessControl::default());
    static ref RT: Runtime = Runtime::new().expect("could not initialize tokio runtime");
    static ref CFG: NssConfig = {
        let mut cfg: NssConfig =  toml::from_slice(std::fs::read(authd::find_config_dir().map(|cd| cd.join("nss_cosiauthd.toml")).expect("no nss_cosiauthd.toml found!")).unwrap().as_slice()).unwrap();
        cfg.cert = shellexpand::full(&cfg.cert).unwrap().to_string();
        cfg
    };
}

struct CauthdPasswd;
impl libnss::passwd::PasswdHooks for CauthdPasswd {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::passwd::Passwd>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_passwd(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> libnss::interop::Response<libnss::passwd::Passwd> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_passwd_by_uid(context::current(), uid)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::passwd::Passwd> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_passwd_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}
struct CauthdShadow;
impl libnss::shadow::ShadowHooks for CauthdShadow {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::shadow::Shadow>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_shadow(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::shadow::Shadow> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_shadow_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}

struct CauthdGroup;
impl libnss::group::GroupHooks for CauthdGroup {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::group::Group>> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_all_groups(context::current())) {
                Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> libnss::interop::Response<libnss::group::Group> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(
            |client| match block_on(client.get_group_by_gid(context::current(), gid)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            },
        )
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::group::Group> {
        let mut cl = RPC.lock().unwrap();
        cl.with_client(|client| {
            match block_on(client.get_group_by_name(context::current(), name)) {
                Ok(passwd) => match passwd {
                    Some(p) => Response::Success(p.to_nss()),
                    None => Response::NotFound,
                },
                Err(_e) => Response::Unavail,
            }
        })
    }
}

use libnss::passwd::PasswdHooks;
#[no_mangle]
extern "C" fn _nss_cosiauthd_setpwent() -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> = PASSWD_ITERATOR.lock().unwrap();

    let status = match CauthdPasswd::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_cosiauthd_endpwent() -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> = PASSWD_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_cosiauthd_getpwent_r(
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> = PASSWD_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_cosiauthd_getpwuid_r(
    uid: libc::uid_t,
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    CauthdPasswd::get_entry_by_uid(uid).to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_cosiauthd_getpwnam_r(
    name_: *const libc::c_char,
    result: *mut CPasswd,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => CauthdPasswd::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}
#[no_mangle]
extern "C" fn _nss_cosiauthd_setgrent() -> c_int {
    let mut iter: MutexGuard<Iterator<Group>> = GROUP_ITERATOR.lock().unwrap();

    let status = match CauthdGroup::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_cosiauthd_endgrent() -> c_int {
    let mut iter: MutexGuard<Iterator<Group>> = GROUP_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_cosiauthd_getgrent_r(
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Group>> = GROUP_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_cosiauthd_getgrgid_r(
    uid: libc::uid_t,
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    CauthdGroup::get_entry_by_gid(uid).to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_cosiauthd_getgrnam_r(
    name_: *const libc::c_char,
    result: *mut CGroup,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => CauthdGroup::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}

use libnss::shadow::{CShadow, Shadow, ShadowHooks};

#[no_mangle]
extern "C" fn _nss_cosiauthd_setspent() -> c_int {
    let mut iter: MutexGuard<Iterator<Shadow>> = SHADOW_ITERATOR.lock().unwrap();

    let status = match CauthdShadow::get_all_entries() {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };

    status as c_int
}

#[no_mangle]
extern "C" fn _nss_cosiauthd_endspent() -> c_int {
    let mut iter: MutexGuard<Iterator<Shadow>> = SHADOW_ITERATOR.lock().unwrap();
    iter.close() as c_int
}

#[no_mangle]
unsafe extern "C" fn _nss_cosiauthd_getspent_r(
    result: *mut CShadow,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Shadow>> = SHADOW_ITERATOR.lock().unwrap();
    iter.next().to_c(result, buf, buflen, errnop) as c_int
}

#[no_mangle]
unsafe extern "C" fn nss_cosiauthd_getspnam_r(
    name_: *const libc::c_char,
    result: *mut CShadow,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name_);

    let response = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => CauthdShadow::get_entry_by_name(name.to_string()),
        Err(_) => Response::NotFound,
    };

    response.to_c(result, buf, buflen, errnop) as c_int
}
