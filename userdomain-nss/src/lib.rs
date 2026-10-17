mod nss;

use core::slice;
use std::{ffi::CStr, iter, mem, net::Ipv4Addr, ptr, time::Duration};
use ::std::os::raw::{c_char, c_int, c_void};

use dbus::blocking::Connection;

use crate::nss::{__errno_location, __socklen_t, AF_INET, EAFNOSUPPORT, ECONNABORTED, ECONNREFUSED, EINVAL, ERANGE, NETDB_INTERNAL, NO_DATA, gaih_addrtuple, hostent, nss_status};

///////////////
// utilities //
///////////////

pub struct SaveErrno(c_int);

impl SaveErrno {
    fn new() -> Self {
        Self(unsafe { *__errno_location() })
    }
}

impl Drop for SaveErrno {
    fn drop(&mut self) {
        unsafe { *__errno_location() = self.0 }
    }
}

macro_rules! nss_guard {
    ($errnop:expr, $herrnop:expr) => {
        let _save_errno = SaveErrno::new();
        macro_rules! nss_return {
            ($errno:expr, $herrno:expr, $status:ident) => {{
                *$errnop = $errno as i32;
                *$herrnop = $herrno as i32;
                return nss_status::$status;
            }}
        }
    }
}

struct CBuffer<'a>(&'a mut [i8]);

impl<'a> CBuffer<'a> {
    unsafe fn new(buffer: *mut c_char, buflen: usize) -> Self {
        Self( if buflen != 0 { unsafe { slice::from_raw_parts_mut(buffer, buflen) } } else { &mut [] } )
    }

    fn alloc<T>(&mut self, count: usize) -> Option<&'a mut [T]> {
        // Technically it is possible to overflow, but we definitely have bigger problem if we
        // actually managed to.
        let padding_len = self.0.as_mut_ptr().align_offset(mem::align_of::<T>());
        let _padding = self.0.split_off_mut(..padding_len)?;

        let slice_len = count * mem::size_of::<T>();
        let slice = self.0.split_off_mut(..slice_len)?;

        Some(unsafe { slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut T, count) })
    }

    fn alloc_one<T>(&mut self) -> Option<&'a mut T> {
        let alloc = &mut self.alloc::<T>(1)?[0];
        Some(alloc)
    }

    fn store_str(&mut self, s: &str) -> Option<&'a mut [i8]> {
        let s = s.as_bytes();
        let s = unsafe { slice::from_raw_parts(s.as_ptr() as *const i8, s.len()) };

        let alloc = self.alloc(s.len()+1)?;
        alloc[..s.len()].copy_from_slice(s);
        alloc[s.len()] = 0;

        Some(alloc)
    }

    fn store_value<T>(&mut self, value: T) -> Option<&'a mut T> {
        let alloc = self.alloc_one()?;
        *alloc = value;
        Some(alloc)
    }
}

///////////////////
// gethostbyname //
///////////////////

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyname_r(name: *const c_char, host: &mut hostent, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int) -> nss_status {
    unsafe { _nss_userdomain_gethostbyname3_r(name, AF_INET as i32, host, buffer, buflen, errnop, herrnop, None, None) } // we only need to support ipv4 address
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyname2_r(name: *const c_char, af: c_int, host: &mut hostent, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int) -> nss_status {
    unsafe { _nss_userdomain_gethostbyname3_r(name, af, host, buffer, buflen, errnop, herrnop, None, None) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyname3_r(name: *const c_char, af: c_int, host: &mut hostent, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int, ttlp: Option<&mut i32>, canonp: Option<&mut *mut c_char>) -> nss_status {
    // Guard
    nss_guard!(errnop, herrnop);

    // Setup.
    let domain = unsafe { CStr::from_ptr(name) };
    let mut buf = unsafe { CBuffer::new(buffer, buflen) };

    // Check if we are even responsible for the name.
    //
    // We response with nss_status::UNAVAIL to allow lookup to continue.
    let Ok(domain) = domain.to_str() else { nss_return!(0, 0, UNAVAIL) };
    if !domain.ends_with(".local") { nss_return!(0, 0, UNAVAIL) }

    // Check if we support the af.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    if af != AF_INET as c_int { nss_return!(EAFNOSUPPORT, NETDB_INTERNAL, NOTFOUND) }

    // Try to connect to dbus service.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let Ok(conn) = Connection::new_system() else { nss_return!(ECONNREFUSED, NETDB_INTERNAL, NOTFOUND) };

    // Resolve the domain via dbus method call.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let proxy = conn.with_proxy("org.UserDomain", "/", Duration::from_millis(5000));
    let Ok((addresses,)): Result<(Vec<u32>,), _> = proxy.method_call("org.UserDomain", "Resolve", (domain,)) else { nss_return!(ECONNABORTED, NETDB_INTERNAL, NOTFOUND) };
    if addresses.is_empty() { nss_return!(0, NO_DATA, NOTFOUND) }

    // Format and return the queried data.
    //
    // Also take care of returning nss_status::TRY_AGAIN with errno set to ERANGE in case the
    // provided buffer is too small.
    {
        let Some(buf_name) = buf.store_str(domain) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        let buf_name = buf_name.as_mut_ptr();
        host.h_name = buf_name;
        let Some(buf_aliases_alloc) = buf.alloc(1) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) } ;
        buf_aliases_alloc[0] = ptr::null_mut();
        host.h_aliases = buf_aliases_alloc.as_mut_ptr();
        host.h_addrtype = AF_INET as i32;
        let Some(buf_addresses_alloc) = buf.alloc(addresses.len()+1) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        for (buf_address_alloc, address) in iter::zip(buf_addresses_alloc.iter_mut(), addresses) {
            let address = Ipv4Addr::from_bits(address);
            let Some(buf_address) = buf.store_value(address) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
            *buf_address_alloc = buf_address as *mut Ipv4Addr as *mut i8;
        }
        buf_addresses_alloc[buf_addresses_alloc.len()-1] = ptr::null_mut(); // Some people have the bright idea that they could skip reading h_length
        host.h_length = (buf_addresses_alloc.len()-1) as i32;
        host.h_addr_list = buf_addresses_alloc.as_mut_ptr();

        if let Some(ttl) = ttlp { *ttl = 0 }
        if let Some(canon) = canonp { *canon = buf_name }
        nss_return!(0, NO_DATA, SUCCESS)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyname4_r(name: *const c_char, pat: &mut Option<&mut gaih_addrtuple>, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int, ttlp: Option<&mut i32>) -> nss_status {
    // Guard
    nss_guard!(errnop, herrnop);

    // Setup.
    let domain = unsafe { CStr::from_ptr(name) };
    let mut buf = unsafe { CBuffer::new(buffer, buflen) };

    // Check if we are even responsible for the name.
    //
    // We response with nss_status::UNAVAIL to allow lookup to continue.
    let Ok(domain) = domain.to_str() else { nss_return!(0, 0, UNAVAIL) };
    if !domain.ends_with(".local") { nss_return!(0, 0, UNAVAIL) }

    // Try to connect to dbus service.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let Ok(conn) = Connection::new_system() else { nss_return!(ECONNREFUSED, NETDB_INTERNAL, NOTFOUND) };

    // Resolve the domain via dbus method call.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let proxy = conn.with_proxy("org.UserDomain", "/", Duration::from_millis(5000));
    let Ok((addresses,)): Result<(Vec<u32>,), _> = proxy.method_call("org.UserDomain", "Resolve", (domain,)) else { nss_return!(ECONNABORTED, NETDB_INTERNAL, NOTFOUND) };
    if addresses.is_empty() { nss_return!(0, NO_DATA, NOTFOUND) }

    // Format and return the queried data.
    //
    // Also take care of returning nss_status::TRY_AGAIN with errno set to ERANGE in case the
    // provided buffer is too small.
    {
        let Some(buf_name) = buf.store_str(domain) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        let buf_name = buf_name.as_mut_ptr();
        let mut last_buf_tuple = None;
        for address in addresses {
            let Some(buf_tuple) = buf.alloc_one::<gaih_addrtuple>() else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
            buf_tuple.next = unsafe { mem::transmute(last_buf_tuple) };
            buf_tuple.name = buf_name;
            buf_tuple.family = AF_INET as i32;
            let address = Ipv4Addr::from_bits(address);
            buf_tuple.addr[0] = u32::from_ne_bytes(address.octets());
            buf_tuple.scopeid = 0;
            last_buf_tuple = Some(buf_tuple);
        }

        if let Some(pat) = pat {
            **pat = *last_buf_tuple.unwrap();
        } else {
            *pat = last_buf_tuple;
        }

        if let Some(ttl) = ttlp { *ttl = 0 }
        nss_return!(0, NO_DATA, SUCCESS)
    }
}

///////////////////
// gethostbyaddr //
///////////////////

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyaddr_r(addr: *const c_void, len: __socklen_t, af: c_int, host: &mut hostent, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int) -> nss_status {
    unsafe { _nss_userdomain_gethostbyaddr2_r(addr, len, af, host, buffer, buflen, errnop, herrnop, None) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_userdomain_gethostbyaddr2_r(addr: *const c_void, len: __socklen_t, af: c_int, host: &mut hostent, buffer: *mut c_char, buflen: usize, errnop: &mut c_int, herrnop: &mut c_int, ttlp: Option<&mut i32>) -> nss_status {
    // Guard
    nss_guard!(errnop, herrnop);

    // Setup.
    let address = unsafe { if len != 0 { slice::from_raw_parts(addr as *const u8, len as usize) } else { &mut [] } };
    let mut buf = unsafe { CBuffer::new(buffer, buflen) };

    // Check if we support the af and the address is correct.
    //
    // We response with nss_status::UNAVAIL to allow lookup to continue.
    if af != AF_INET as c_int { nss_return!(EAFNOSUPPORT, NETDB_INTERNAL, UNAVAIL) }
    if address.len() != mem::size_of::<Ipv4Addr>() { nss_return!(EINVAL, NETDB_INTERNAL, UNAVAIL)  }
    let address: Ipv4Addr = Ipv4Addr::from_octets(address.try_into().unwrap());

    // Check if we are even responsible for the address. For now, this is hard-coded to mean that we
    // are from 127.0.0.1/24 except 127.0.0.1.
    //
    // We response with nss_status::UNAVAIL to allow lookup to continue.
    if address.octets()[0] != 127 { nss_return!(0, 0, UNAVAIL) };
    if address.octets()[3] == 1   { nss_return!(0, 0, UNAVAIL) };
    let address = address.to_bits();

    // Try to connect to dbus service.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let Ok(conn) = Connection::new_system() else { nss_return!(ECONNREFUSED, NETDB_INTERNAL, NOTFOUND) };

    // Resolve the domain via dbus method call.
    //
    // We response with nss_status::NOTFOUND to indicate that we want to prevent further lookup.
    let proxy = conn.with_proxy("org.UserDomain", "/", Duration::from_millis(5000));
    let Ok((domain,)): Result<(String,), _> = proxy.method_call("org.UserDomain", "ReverseResolve", (address,)) else { nss_return!(ECONNABORTED, NETDB_INTERNAL, NOTFOUND) };

    // Format and return the queried data.
    //
    // Also take care of returning nss_status::TRY_AGAIN with errno set to ERANGE in case the
    // provided buffer is too small.
    {
        let Some(buf_name) = buf.store_str(&domain) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        let buf_name = buf_name.as_mut_ptr();
        host.h_name = buf_name;
        host.h_aliases = ptr::null_mut();
        host.h_addrtype = AF_INET as i32;
        let address = Ipv4Addr::from_bits(address);
        let Some(buf_address) = buf.store_value(address) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        let Some(buf_addresses) = buf.store_value(buf_address) else { nss_return!(ERANGE, NETDB_INTERNAL, TRYAGAIN) };
        host.h_length = 1;
        host.h_addr_list = unsafe { mem::transmute(buf_addresses) /* SAFETY: Trust me bro */ };

        if let Some(ttl) = ttlp { *ttl = 0 }
        nss_return!(0, NO_DATA, SUCCESS)
    }
}

