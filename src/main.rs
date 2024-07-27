use core::str;
use serde_json::{self, json, Value};
use sha1::{Digest, Sha1};
use std::{env, fs, path::Path};

#[allow(dead_code)]
fn decode_bencoded_value(
    encoded_value: &[u8],
    info_hash_meta: &mut HelperInfo,
) -> (serde_json::Value, usize) {
    match encoded_value.iter().next() {
        Some(str_len) if str_len.is_ascii_digit() => {
            // example 5:asdfs
            // mostly it will be valid utf8 string (char code)
            let colon_index = encoded_value.iter().position(|&x| x == b':').unwrap();
            let num_str = str::from_utf8(&encoded_value[..colon_index]);
            let number = i64::from_str_radix(num_str.unwrap(), 10).unwrap();
            let end_idx = colon_index + 1 + number as usize;
            let target_slice = &encoded_value[colon_index + 1..end_idx];

            // it will be invalid utf8 if it was a key 'pieces', return array in that case
            // you can use unsafe string, but it will not be checked and string will panic
            if info_hash_meta.was_pieces_key {
                return (json!(target_slice), end_idx);
            }
            // strings are valid utf8-encoded byte slice
            let string = String::from_utf8(target_slice.to_vec()).unwrap();
            return (json!(string), end_idx);
        }
        Some(i) if *i == b'i' => {
            let end_index = encoded_value.iter().position(|&x| x == b'e').unwrap();
            let num_str = str::from_utf8(&encoded_value[1..end_index]);
            let number = i64::from_str_radix(num_str.unwrap(), 10).unwrap();
            return (json!(number), end_index + 1);
        }
        Some(c) if *c == b'l' => {
            let mut list = Vec::new();
            let mut remaining = &encoded_value[1..];
            let mut len = 1;
            while !remaining.is_empty() {
                // println!("{remaining:?}");
                if *remaining.iter().next().unwrap() == b'e' {
                    break;
                }
                let (value, val_len) = decode_bencoded_value(remaining, info_hash_meta);
                len += val_len;
                list.push(value);
                remaining = &remaining[val_len..];
            }
            return (json!(list), len + 1);
        }
        Some(c) if *c == b'd' => {
            let mut dict: serde_json::Map<std::string::String, serde_json::Value> =
                serde_json::Map::new();
            let mut remaining = &encoded_value[1..];
            let mut len = 1;
            while !remaining.is_empty() {
                if *remaining.iter().next().unwrap() == b'e' {
                    break;
                }
                let (key, key_len) = decode_bencoded_value(&remaining, info_hash_meta);
                len += key_len;
                remaining = &remaining[key_len..];

                let key_val = key.as_str().unwrap();
                if key_val == "pieces" {
                    info_hash_meta.was_pieces_key = true;
                }
                if key_val == "info" {
                    // println!("Found info at {}", info_hash_meta.start);
                    info_hash_meta.found_info_start = true;
                    info_hash_meta.info_start += 6; // avoid 4:info
                }
                // println!("key_len {}", key_len);

                let (val, val_len) = decode_bencoded_value(&remaining, info_hash_meta);
                len += val_len;
                dict.insert(key.as_str().unwrap().to_owned(), val);
                if info_hash_meta.found_info_start {
                    info_hash_meta.info_end = info_hash_meta.info_start + val_len;
                }

                remaining = &remaining[val_len..];
                // println!("{dict:?} {remaining:?}");

                // accumulate start index if have not found the start of info_dict
                if !info_hash_meta.found_info_start {
                    info_hash_meta.info_start += val_len + key_len; // add key + value + colon
                }
            }
            return (json!(dict), len + 1);
        }
        _ => (serde_json::Value::Null, 0),
    }
}

/*
announce: URL to a "tracker", which is a central server that keeps track of peers participating in the sharing of a torrent.
info: A dictionary with keys:
    length: size of the file in bytes, for single-file torrents
    name: suggested name to save the file / directory as
    piece length: number of bytes in each piece
    pieces: concatenated SHA-1 hashes of each piece
 */
struct MetaInfo {
    announce: String,
    length: String,
    info_hash: String,
}

struct HelperInfo {
    info_start: usize,
    info_end: usize,
    found_info_start: bool,
    was_pieces_key: bool,
}

impl HelperInfo {
    fn new() -> Self {
        HelperInfo {
            info_start: 1, // exclude first d
            info_end: 0,
            found_info_start: false,
            was_pieces_key: false,
        }
    }
}

// https://www.bittorrent.org/beps/bep_0003.html
fn read_torrent_info(filename: &str) -> Option<MetaInfo> {
    let path = Path::new(filename);
    match fs::read(path) {
        Ok(encoded_value) => {
            let mut info_hash_meta = HelperInfo::new();
            let (decoded_value, _len) =
                decode_bencoded_value(encoded_value.as_slice(), &mut info_hash_meta);

            // println!("{:?}", decoded_value);
            let url = decoded_value.get("announce")?.to_string();
            let info_dict = decoded_value.get("info")?;
            let length = info_dict.get("length")?.to_string();

            let info_dict_slice =
                &encoded_value[info_hash_meta.info_start..info_hash_meta.info_end];
            // println!("debug {}", String::from_utf8_lossy(info_dict));
            let meta_info = MetaInfo {
                announce: remove_json_quote(url),
                length,
                info_hash: get_info_hash(info_dict_slice),
            };

            let url = &meta_info.announce;
            let len = &meta_info.length;
            let info_hash = &meta_info.info_hash;
            let piece_len = info_dict.get("piece length")?.to_string();
            println!("Tracker URL: {url}");
            println!("Length: {len}");
            println!("Info Hash: {info_hash}");
            println!("Piece Length: {}", piece_len);
            println!("Piece Hashes:");
            if let Some(pieces_arr) = info_dict.get("pieces")?.as_array() {
                print_piece_hashes(pieces_arr);
            }
            Some(meta_info)
        }
        Err(e) => {
            println!("Read failed: {:?}", e);
            return None;
        }
    }
}

use std::fmt::Write;

fn print_piece_hashes(pieces: &Vec<Value>) {
    if pieces.len() % 20 != 0 {
        println!(
            "Invalid pieces field: length is not a multiple of 20 {}",
            pieces.len()
        );
        return;
    }
    let bytes: Vec<u8> = pieces
        .into_iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();

    let piece_hashes = bytes.chunks(20); // [i64; 2000] to [[i64; 20]; 100]
    for hash in piece_hashes {
        let mut hash_str = String::new();
        for byte in hash {
            write!(&mut hash_str, "{:02x}", byte).unwrap();
        }
        println!("{}", hash_str);
    }
}

fn get_info_hash(info_dict: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(info_dict);
    let result = hasher.finalize();

    let mut sha1_hash = String::new();
    for byte in result.as_slice() {
        let c = format!("{:02x}", byte);
        sha1_hash.extend([c]);
    }
    sha1_hash
}

fn remove_json_quote(s: String) -> String {
    s[1..s.len() - 1].to_owned()
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];
    match command.as_str() {
        "decode" => {
            let mut _a = HelperInfo::new();
            let encoded_value = &args[2];
            let (decoded_value, _len) = decode_bencoded_value(encoded_value.as_bytes(), &mut _a);
            println!("{}", decoded_value.to_string());
        }
        "info" => {
            let filename = &args[2];
            let _meta_info = read_torrent_info(filename);
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
