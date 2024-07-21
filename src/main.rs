use serde_json::{self, json};
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, usize) {
    // If encoded_value starts with a digit, it's a number
    match encoded_value.chars().next() {
        Some(str_len) if str_len.is_digit(10) => {
            let colon_index = encoded_value.find(':').unwrap();
            let number_string = &encoded_value[..colon_index];
            let number = number_string.parse::<i64>().unwrap();
            let end_idx = colon_index + 1 + number as usize;
            let string: &str = &encoded_value[colon_index + 1..end_idx];
            return (serde_json::Value::String(string.to_string()), end_idx);
        }
        Some(i) if i == 'i' => {
            let end_index = encoded_value.find('e').unwrap();
            let num = &encoded_value[1..end_index].parse::<i64>().unwrap();
            return (json!(num), end_index + 1);
        }
        Some(c) if c == 'l' => {
            let mut list = Vec::new();
            let mut remaining = &encoded_value[1..];
            let mut len = 0;
            while !remaining.is_empty() {
                // println!("{remaining:?}");
                if remaining.starts_with('e') {
                    break;
                }
                let (value, val_len) = decode_bencoded_value(remaining);
                len += val_len;
                list.push(value);
                remaining = &remaining[val_len..];
            }
            return (json!(list), len + 2);
        }
        _ => (serde_json::Value::Null, 0),
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let (decoded_value, _len) = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
