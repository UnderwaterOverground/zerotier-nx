//! Standalone TLS sessions over the C ABI. The C side owns the socket and
//! shuttles bytes; used by the GitHub update check.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};

use ztnx_core::tls::{self, TlsClient};

pub struct ZtnxTls {
    client: TlsClient,
    out: Vec<u8>,
    plain: Vec<u8>,
    error: Vec<u8>,
}

pub const ZTNX_TLS_ESTABLISHED: u32 = 1;
pub const ZTNX_TLS_PEER_CLOSED: u32 = 2;
pub const ZTNX_TLS_FAILED: u32 = 4;

impl ZtnxTls {
    fn fail(&mut self, e: tls::TlsError) -> i32 {
        let mut msg = format!("{e:?}").into_bytes();
        msg.push(0);
        self.error = msg;
        -1
    }

    fn collect(&mut self) {
        self.out.extend(self.client.take_outgoing());
        self.plain.extend(self.client.take_plaintext());
    }
}

/// Starts a TLS 1.3 session to `server_name`. Returns NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_new(server_name: *const c_char) -> *mut ZtnxTls {
    let Ok(name) = CStr::from_ptr(server_name).to_str() else {
        return core::ptr::null_mut();
    };
    let Ok(config) = tls::client_config(&[]) else {
        return core::ptr::null_mut();
    };
    match TlsClient::new(config, name) {
        Ok(client) => {
            let mut s = Box::new(ZtnxTls { client, out: Vec::new(), plain: Vec::new(), error: Vec::new() });
            s.collect();
            Box::into_raw(s)
        }
        Err(_) => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_free(s: *mut ZtnxTls) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Feeds ciphertext read from the socket. Returns 0, or -1 on a TLS error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_feed(s: *mut ZtnxTls, data: *const u8, len: usize) -> i32 {
    let s = &mut *s;
    let r = s.client.feed(core::slice::from_raw_parts(data, len));
    s.collect();
    match r {
        Ok(()) => 0,
        Err(e) => s.fail(e),
    }
}

/// Queues plaintext for encryption. Returns 0, or -1 on a TLS error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_write(s: *mut ZtnxTls, data: *const u8, len: usize) -> i32 {
    let s = &mut *s;
    let r = s.client.write(core::slice::from_raw_parts(data, len));
    s.collect();
    match r {
        Ok(()) => 0,
        Err(e) => s.fail(e),
    }
}

fn drain_into(src: &mut Vec<u8>, buf: *mut u8, cap: usize) -> usize {
    let n = src.len().min(cap);
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), buf, n) };
    src.drain(..n);
    n
}

/// Copies up to `cap` bytes of pending ciphertext to send. Returns the count.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_take_outgoing(s: *mut ZtnxTls, buf: *mut u8, cap: usize) -> usize {
    drain_into(&mut (*s).out, buf, cap)
}

/// Copies up to `cap` bytes of decrypted plaintext. Returns the count.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_read(s: *mut ZtnxTls, buf: *mut u8, cap: usize) -> usize {
    drain_into(&mut (*s).plain, buf, cap)
}

/// Returns a bitmask of ZTNX_TLS_* flags.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_state(s: *const ZtnxTls) -> u32 {
    let s = &*s;
    let mut flags = 0;
    if s.client.is_established() {
        flags |= ZTNX_TLS_ESTABLISHED;
    }
    if s.client.peer_closed() {
        flags |= ZTNX_TLS_PEER_CLOSED;
    }
    if !s.error.is_empty() {
        flags |= ZTNX_TLS_FAILED;
    }
    flags
}

/// The last error message (NUL-terminated), or "" if none.
#[no_mangle]
pub unsafe extern "C" fn ztnx_tls_last_error(s: *const ZtnxTls) -> *const c_char {
    let s = &*s;
    if s.error.is_empty() {
        c"".as_ptr()
    } else {
        s.error.as_ptr().cast()
    }
}

