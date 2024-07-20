use serde_json::{self, json};
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    // If encoded_value starts with a digit, it's a number
    match encoded_value.chars().next() {
        Some(str_len) if str_len.is_digit(10) => {
            let colon_index = encoded_value.find(':').unwrap();
            let number_string = &encoded_value[..colon_index];
            let number = number_string.parse::<i64>().unwrap();
            let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
            return serde_json::Value::String(string.to_string());
        }
        Some(i) if i == 'i' => {
            let end_index = encoded_value.find('e').unwrap();
            let num = &encoded_value[1..end_index].parse::<i64>().unwrap();
            return json!(num);
        }
        Some(c) if c == 'l' => {
            let mut list = Vec::new();
            let mut remaining = &encoded_value[1..];
            while !remaining.is_empty() {
                if remaining.starts_with('e') {
                    remaining = &remaining[1..];
                    break;
                }
                let value = decode_bencoded_value(remaining).to_string();
                let rem = value.to_string().len();
                list.push(value);
                remaining = &remaining[rem..];
            }
            return json!(list);
        }
        _ => serde_json::Value::Null,
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
