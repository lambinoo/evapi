use std::convert::TryFrom;
use std::mem::transmute;
use std::{ffi::CString, mem::size_of};

use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, WORD};
use winapi::um::ipexport::{IPAddr, ICMP_ECHO_REPLY, PIP_OPTION_INFORMATION};
use winapi::{
    shared::ntdef::{HANDLE, NULL},
    um::libloaderapi::{GetProcAddress, LoadLibraryA},
};

type TypeIcmpCreateHandle = unsafe extern "system" fn() -> HANDLE;
type TypeIcmpCloseHandle = unsafe extern "system" fn(HANDLE) -> bool;
type TypeIcmpSendEcho2 = unsafe extern "system" fn(
    handle: HANDLE,
    event: HANDLE,
    apc_routine: *const c_void,
    apc_context: *const c_void,
    dst: IPAddr,
    request_data: *const u8,
    request_size: WORD,
    request_options: *const PIP_OPTION_INFORMATION,
    reply_buffer: *mut u8,
    reply_size: DWORD,
    timeout: DWORD,
) -> DWORD;

lazy_static! {
    static ref REAL_ICMP_CREATE_HANDLE: TypeIcmpCreateHandle = unsafe {
        let lib_name = CString::new(obfstr::obfstr!("iphlpapi")).expect("");
        let fn_name = CString::new(obfstr::obfstr!("IcmpCreateFile")).expect("");
        let lib = LoadLibraryA(lib_name.as_ptr());
        transmute(GetProcAddress(lib, fn_name.as_ptr()))
    };
    static ref REAL_ICMP_SEND_ECHO2: TypeIcmpSendEcho2 = unsafe {
        let lib_name = CString::new(obfstr::obfstr!("iphlpapi")).unwrap();
        let fn_name = CString::new(obfstr::obfstr!("IcmpSendEcho2")).unwrap();
        let lib = LoadLibraryA(lib_name.as_ptr());
        transmute(GetProcAddress(lib, fn_name.as_ptr()))
    };
    static ref REAL_ICMP_CLOSE_HANDLE: TypeIcmpCloseHandle = unsafe {
        let lib_name = CString::new(obfstr::obfstr!("iphlpapi")).unwrap();
        let fn_name = CString::new(obfstr::obfstr!("IcmpCloseHandle")).unwrap();
        let lib = LoadLibraryA(lib_name.as_ptr());
        transmute(GetProcAddress(lib, fn_name.as_ptr()))
    };
}

#[derive(Debug)]
pub struct IcmpHandle {
    handle: HANDLE,
}

impl IcmpHandle {
    /// Create new Icmp Handle to allow for sending payloads through icmp
    pub fn new() -> IcmpHandle {
        let handle = unsafe { REAL_ICMP_CREATE_HANDLE() };
        IcmpHandle { handle }
    }

    pub fn send(&self, dst: std::net::Ipv4Addr, data: &[u8], timeout: usize) -> Option<Vec<u8>> {
        let reply_buffer_size = size_of::<ICMP_ECHO_REPLY>() + data.len();
        let mut reply_buffer = Vec::with_capacity(reply_buffer_size);

        let return_value = unsafe {
            reply_buffer.set_len(reply_buffer_size);

            REAL_ICMP_SEND_ECHO2(
                self.handle,
                NULL,
                NULL,
                NULL,
                IPAddr::from(dst),
                data.as_ptr(),
                WORD::try_from(data.len()).expect(""),
                NULL as _,
                reply_buffer.as_mut_ptr(),
                DWORD::try_from(reply_buffer_size).expect(""),
                DWORD::try_from(timeout).expect(""),
            )
        };

        if return_value > 0 {
            Some(reply_buffer)
        } else {
            None
        }
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        unsafe {
            REAL_ICMP_CLOSE_HANDLE(self.handle);
        }
    }
}
