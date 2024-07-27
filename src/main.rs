use core::str;
use serde_json::{self, json};
use std::{env, fs, path::Path};

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &[u8]) -> (serde_json::Value, usize) {
    // If encoded_value starts with a digit, it's a number
    match encoded_value.iter().next() {
        Some(str_len) if str_len.is_ascii_digit() => {
            // example 5:asdfs
            let colon_index = encoded_value.iter().position(|&x| x == b':').unwrap();
            let num_str = str::from_utf8(&encoded_value[..colon_index]);
            let number = i64::from_str_radix(num_str.unwrap(), 10).unwrap();
            let end_idx = colon_index + 1 + number as usize;
            let string = String::from_utf8_lossy(&encoded_value[colon_index + 1..end_idx]);
            return (json!(string.to_string()), end_idx);
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
                let (value, val_len) = decode_bencoded_value(remaining);
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
                let (key, key_len) = decode_bencoded_value(&remaining);
                len += key_len;
                remaining = &remaining[key_len..];

                let (val, val_len) = decode_bencoded_value(&remaining);
                len += val_len;
                dict.insert(key.as_str().unwrap().to_owned(), val);

                remaining = &remaining[val_len..];
                // println!("{dict:?} {remaining:?}");
            }
            return (json!(dict), len + 1);
        }
        _ => (serde_json::Value::Null, 0),
    }
}

fn read_torrent_info(filename: &str) -> Option<(String, String)> {
    let path = Path::new(filename);
    match fs::read(path) {
        Ok(encoded_value) => {
            let (decoded_value, _len) = decode_bencoded_value(encoded_value.as_slice());
            // println!("{:?}", decoded_value);
            let url = decoded_value.get("announce")?.to_string();
            let length = decoded_value.get("info")?.get("length")?.to_string();
            Some((remove_json_quote(url), length))
        }
        Err(e) => {
            println!("Read failed: {:?}", e);
            return None;
        }
    }
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
            let encoded_value = &args[2];
            let (decoded_value, _len) = decode_bencoded_value(encoded_value.as_bytes());
            println!("{}", decoded_value.to_string());
        }
        "info" => {
            let filename = &args[2];
            let (url, len) = read_torrent_info(filename).unwrap();
            println!("Tracker URL: {url}\nLength: {len}");
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
