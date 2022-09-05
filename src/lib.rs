use libnss::{libnss_passwd_hooks, passwd::PasswdHooks};

struct CauthdPasswd;
impl PasswdHooks for CauthdPasswd {
    fn get_all_entries() -> libnss::interop::Response<Vec<libnss::passwd::Passwd>> {
        Response::Success(vec![])
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> libnss::interop::Response<libnss::passwd::Passwd> {
        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> libnss::interop::Response<libnss::passwd::Passwd> {
        Response::NotFound
    }
}

use libc::c_int;
use libnss::interop::{CBuffer, Iterator, Response};
use libnss::passwd::{CPasswd, Passwd};
use std::ffi::CStr;
use std::str;
use std::sync::{Mutex, MutexGuard};

lazy_static::lazy_static! {
    static ref PASSWD_ITERATOR: Mutex<Iterator<Passwd>> = Mutex::new(Iterator::<Passwd>::new());
}

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
