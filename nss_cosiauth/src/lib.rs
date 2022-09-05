use authd::types::ToNSS;
use futures::executor::block_on;
use libc::c_int;
use libnss::group::{CGroup, Group, GroupHooks};
use libnss::interop::{CBuffer, Iterator, Response};
use libnss::passwd::{CPasswd, Passwd};
use std::ffi::CStr;
use std::str;
use std::sync::{Arc, Mutex, MutexGuard};
use tarpc::context;

lazy_static::lazy_static! {
    static ref PASSWD_ITERATOR: Mutex<Iterator<Passwd>> = Mutex::new(Iterator::<Passwd>::new());
    static ref GROUP_ITERATOR: Mutex<Iterator<Group>> = Mutex::new(Iterator::<Group>::new());

    static ref RPC: Mutex<authd::rpc::AuthdClient> = {

    let transport = tarpc::serde_transport::tcp::connect(("127.0.0.1", 8080), tarpc::tokio_serde::formats::Json::default);

    let client = authd::rpc::AuthdClient::new(tarpc::client::Config::default(), futures::executor::block_on(transport).unwrap()).spawn();
        Mutex::new(client)
    };
}

struct CauthdPasswd;
impl libnss::passwd::PasswdHooks for CauthdPasswd {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::passwd::Passwd>> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_all_passwd(context::current())) {
            Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
            Err(_e) => Response::Unavail,
        }
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> libnss::interop::Response<libnss::passwd::Passwd> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_passwd_by_uid(context::current(), uid)) {
            Ok(passwd) => match passwd {
                Some(p) => Response::Success(p.to_nss()),
                None => Response::NotFound,
            },
            Err(_e) => Response::Unavail,
        }
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::passwd::Passwd> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_passwd_by_name(context::current(), name)) {
            Ok(passwd) => match passwd {
                Some(p) => Response::Success(p.to_nss()),
                None => Response::NotFound,
            },
            Err(_e) => Response::Unavail,
        }
    }
}

struct CauthdGroup;
impl libnss::group::GroupHooks for CauthdGroup {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::group::Group>> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_all_groups(context::current())) {
            Ok(passwds) => Response::Success(passwds.into_iter().map(|x| x.to_nss()).collect()),
            Err(_e) => Response::Unavail,
        }
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> libnss::interop::Response<libnss::group::Group> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_group_by_gid(context::current(), gid)) {
            Ok(passwd) => match passwd {
                Some(p) => Response::Success(p.to_nss()),
                None => Response::NotFound,
            },
            Err(_e) => Response::Unavail,
        }
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::group::Group> {
        let client = RPC.lock().unwrap();
        match block_on(client.get_group_by_name(context::current(), name)) {
            Ok(passwd) => match passwd {
                Some(p) => Response::Success(p.to_nss()),
                None => Response::NotFound,
            },
            Err(_e) => Response::Unavail,
        }
    }
}

use libnss::passwd::PasswdHooks;
#[no_mangle]
extern "C" fn _nss_cosiauthd_setpwent() -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> = PASSWD_ITERATOR.lock().unwrap();

    let status = match (CauthdPasswd::get_all_entries()) {
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

    let status = match (CauthdGroup::get_all_entries()) {
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
