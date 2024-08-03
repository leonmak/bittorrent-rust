use core::str;

use serde_json::json;

use crate::HelperInfo;

#[allow(dead_code)]
pub fn decode_bencoded_value(
    encoded_value: &[u8],
    helper: &mut HelperInfo,
) -> (serde_json::Value, usize) {
    // println!("[u8]:{:?}", encoded_value);
    // println!("enc: {:?}", String::from_utf8_lossy(encoded_value));

    match encoded_value.iter().next() {
        Some(str_len) if str_len.is_ascii_digit() => {
            // example 5:asdfs, num:val (num is bytes in payload, utf8 chars may have >1 byte)
            // parse value is string or byte array (peers/pieces)
            let colon_index = encoded_value.iter().position(|&x| x == b':').unwrap();
            let num_str = str::from_utf8(&encoded_value[..colon_index]);
            let num_chars = usize::from_str_radix(num_str.unwrap(), 10).unwrap();
            let start_idx = colon_index + 1;
            // println!("{} || {:?}", num_chars, target_slice);

            // it will be invalid utf8 if it was a key 'pieces', return array in that case
            // you can use unsafe string, but it will not be checked and string will panic
            if helper.is_bytes_val {
                let end_idx = start_idx + num_chars;
                helper.is_bytes_val = false;
                let val = &encoded_value[start_idx..end_idx];
                (json!(val), end_idx)
            } else {
                // strings are valid utf8-encoded byte slice
                let end_idx = start_idx + num_chars;
                let target_slice = &encoded_value[start_idx..end_idx];
                let string = String::from_utf8(target_slice.to_vec()).unwrap();
                (json!(string), end_idx)
            }
        }
        Some(i) if *i == b'i' => {
            let end_index: usize = encoded_value.iter().position(|&x| x == b'e').unwrap();
            let is_neg = encoded_value[1] == b'-';
            let start_index = if is_neg { 2 } else { 1 };
            let num_str = str::from_utf8(&encoded_value[start_index..end_index]);
            let number = i64::from_str_radix(num_str.unwrap(), 10).unwrap();
            // println!("int {}", number);
            return (json!(if is_neg { -1 } else { 1 } * number), end_index + 1);
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
                let (value, val_len) = decode_bencoded_value(remaining, helper);
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
                if remaining[0] == b'e' {
                    len += 1;
                    break;
                }
                let (key, key_len) = decode_bencoded_value(&remaining, helper);
                len += key_len;
                remaining = &remaining[key_len..];
                // println!("key:'{}' ", key);
                let key_val = key.as_str().unwrap();
                helper.is_bytes_val = key_val == "pieces" || key_val == "peers";
                if key_val == "info" {
                    // println!("Found info at {}", info_hash_meta.start);
                    helper.found_info_start = true;
                    helper.info_start += 6; // avoid 4:info
                }
                // println!("key_len {}", key_len);

                let (val, val_len) = decode_bencoded_value(&remaining, helper);
                // println!(" val:{}", val);
                len += val_len;
                dict.insert(key.as_str().unwrap().to_owned(), val);
                if helper.found_info_start {
                    helper.info_end = helper.info_start + val_len;
                }

                remaining = &remaining[val_len..];
                // println!("dict {dict:?}");
                // println!("remaining {remaining:?}");

                // accumulate start index if have not found the start of info_dict
                if !helper.found_info_start {
                    helper.info_start += val_len + key_len; // add key + value + colon
                }
            }
            return (json!(dict), len);
        }
        _ => {
            panic!("invalid value")
        }
    }
}
