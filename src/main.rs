use core::str;
use reqwest::blocking::get;
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};
use sha1::{Digest, Sha1};
use std::fs::OpenOptions;
use std::io::{Cursor, Write as _};
use std::net::TcpStream;
use std::{env, fs, path::Path};

#[allow(dead_code)]
fn decode_bencoded_value(
    encoded_value: &[u8],
    helper: &mut HelperInfo,
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
            if helper.is_bytes_val {
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
                if *remaining.iter().next().unwrap() == b'e' {
                    break;
                }
                let (key, key_len) = decode_bencoded_value(&remaining, helper);
                len += key_len;
                remaining = &remaining[key_len..];
                print!("key:{}", key);
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
                // println!("{dict:?} {remaining:?}");

                // accumulate start index if have not found the start of info_dict
                if !helper.found_info_start {
                    helper.info_start += val_len + key_len; // add key + value + colon
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

#[derive(Debug)]
struct MetaInfo {
    announce: String,
    length: String,
    info_hash: String,
    piece_len: String,
    piece_hashes: Vec<String>,
}

struct HelperInfo {
    info_start: usize,
    info_end: usize,
    found_info_start: bool,
    is_bytes_val: bool,
}

impl HelperInfo {
    fn new() -> Self {
        HelperInfo {
            info_start: 1, // exclude first d
            info_end: 0,
            found_info_start: false,
            is_bytes_val: false,
        }
    }
}

// https://www.bittorrent.org/beps/bep_0003.html
fn read_torrent_info(filename: &str) -> Option<MetaInfo> {
    let path = Path::new(filename);
    match fs::read(path) {
        Ok(encoded_value) => {
            let mut helper = HelperInfo::new();
            let (decoded_value, _len) =
                decode_bencoded_value(encoded_value.as_slice(), &mut helper);

            // println!("{:?}", decoded_value);
            let url = decoded_value.get("announce")?.to_string();
            let info_dict = decoded_value.get("info")?.clone();
            let length = info_dict.get("length")?.to_string();

            let info_dict_slice = &encoded_value[helper.info_start..helper.info_end];
            // println!("debug {}", String::from_utf8_lossy(info_dict));
            let piece_len = info_dict.get("piece length")?.to_string();
            let piece_hashes = info_dict.get("pieces")?.as_array()?.clone();
            let meta_info = MetaInfo {
                announce: remove_json_quote(url),
                length,
                info_hash: get_sha1(info_dict_slice),
                piece_len,
                piece_hashes: pieces_sha1(piece_hashes),
            };

            Some(meta_info)
        }
        Err(e) => {
            println!("Read failed: {:?}", e);
            return None;
        }
    }
}

use std::fmt::Write;

fn pieces_sha1(pieces: Vec<Value>) -> Vec<String> {
    if pieces.len() % 20 != 0 {
        println!(
            "Invalid pieces field: length is not a multiple of 20 {}",
            pieces.len()
        );
        return vec![];
    }
    let bytes: Vec<u8> = pieces
        .into_iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();

    let mut res: Vec<String> = vec![];

    let piece_hashes = bytes.chunks(20); // [i64; 2000] to [[i64; 20]; 100]
    for hash in piece_hashes {
        let mut hash_str = String::new();
        for byte in hash {
            write!(&mut hash_str, "{:02x}", byte).unwrap();
        }
        res.push(hash_str)
    }
    res
}

fn get_sha1(byte_slice: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(byte_slice);
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

fn hex_str_as_bytes(hex_str: &str) -> Vec<u8> {
    // convert every 2 chars into a hex u8
    let mut res: Vec<u8> = Vec::new();
    for i in 0..hex_str.len() / 2 {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
        res.push(byte);
    }
    res
}

fn hex_to_enc(hex_str: &str) -> String {
    let mut url = String::new();
    for chunk in hex_str.as_bytes().chunks(2) {
        url.push_str("%");
        let from_utf8 = String::from_utf8(chunk.to_vec()).unwrap();
        url.push_str(&from_utf8);
    }
    url
}

#[derive(Deserialize, Serialize, Debug)]
struct PeerInfo {
    interval: u64,
    peers: Vec<u8>,
}

fn get_tracker_url(meta: &MetaInfo) -> Option<String> {
    let info_hash = meta.info_hash.clone();
    let url = format!(
        "{}?info_hash={}&peer_id=00112233445566778899&port=6881&uploaded=0&downloaded=0&compact=1&left={}",
        meta.announce, hex_to_enc(info_hash.as_str()), meta.length
    );
    Some(url)
}

fn read_peer_url(meta_info: &MetaInfo) -> Result<PeerInfo, reqwest::Error> {
    let url = get_tracker_url(meta_info).unwrap();
    println!("Fetching Tracker: {}", url);
    let response = get(url).unwrap();
    let bytes = response.bytes()?;
    let bytes = bytes.as_ref();
    let mut helper_info = HelperInfo::new();
    let (peer_info_dict, _size) = decode_bencoded_value(&bytes.to_vec(), &mut helper_info);
    println!("debug {}", peer_info_dict);
    let peer_info: PeerInfo = serde_json::from_value(peer_info_dict).unwrap();
    Ok(peer_info)
}

fn fmt_ip_str(ip_str: Vec<u8>) -> Vec<String> {
    // first 4 bytes are ip address, last 2 bytes are port
    let mut res: Vec<String> = Vec::new();
    for bytes in ip_str.chunks(6) {
        let ip_bytes = &bytes[..4];
        let port_bytes = &bytes[4..];
        let ip = format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        );
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        res.push(format!("{}:{}", ip, port));
    }
    res
}

#[derive(Debug)]
struct HandshakeMessage {
    pstr_len: u8,
    pstr: [u8; 19],
    reserved: [u8; 8],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
}

use std::io::Read as _;
fn read_handshake_message<R: std::io::Read>(reader: &mut R) -> std::io::Result<HandshakeMessage> {
    let mut handshake = HandshakeMessage {
        pstr_len: 0,
        pstr: [0; 19],
        reserved: [0; 8],
        info_hash: [0; 20],
        peer_id: [0; 20],
    };
    reader.read_exact(std::slice::from_mut(&mut handshake.pstr_len))?;
    reader.read_exact(&mut handshake.pstr)?;
    reader.read_exact(&mut handshake.reserved)?;
    reader.read_exact(&mut handshake.info_hash)?;
    reader.read_exact(&mut handshake.peer_id)?;

    Ok(handshake)
}

fn send_handshake(mut stream: &TcpStream, info_hash: &str) -> String {
    // send a message with TCP
    let peer_id = "00112233445566778899"; // My Peer ID (20 bytes)

    let mut handshake_msg = Vec::new();
    handshake_msg.push(19); // Length of the protocol string (1 byte)
    handshake_msg.extend_from_slice(b"BitTorrent protocol"); // Protocol string (19 bytes)
    handshake_msg.extend_from_slice(&[0u8; 8]); // Reserved bytes (8 bytes)
    handshake_msg.extend_from_slice(hex_str_as_bytes(info_hash).as_slice()); // Info hash (20 bytes)
    handshake_msg.extend_from_slice(peer_id.as_bytes()); // Peer ID (20 bytes)
    println!("Sending {} bytes", handshake_msg.len());
    // Send the handshake message
    stream
        .write_all(&handshake_msg)
        .expect("Failed to send handshake");

    // Read the response from the peer
    let mut response = [0u8; 68];
    stream
        .read_exact(&mut response)
        .expect("Failed to read response");

    let mut cursor = Cursor::new(response);
    let handshake = read_handshake_message(&mut cursor).expect("Failed to read handshake message");
    // print each byte as its hex char
    println!("{:?}", handshake);
    format!(
        "{}",
        handshake.peer_id.map(|f| format!("{:02x}", f)).join("")
    )
}

const CHUNK_SIZE: usize = 1 << 14;
fn download_piece(mut stream: &TcpStream, hashes: &Vec<String>, output_fn: &str) {
    // message = length prefix (4 bytes), message id (1 byte), payload (variable size)

    // recv bitfield
    let mut len_prefix: [u8; 4] = [0; 4];
    let mut msg_id: [u8; 1] = [0; 1];
    stream.read_exact(&mut len_prefix).expect("Read len failed");
    stream.read_exact(&mut msg_id).expect("msg_id failed");

    let mut message_length = u32::from_be_bytes(len_prefix) as usize;
    println!("bitfield len: {}, id: {}", message_length, msg_id[0]);

    // Read the bitfield payload - 1 means have piece
    let mut bitfield = Vec::with_capacity(message_length);
    stream.read_exact(&mut bitfield).expect("read bitfield");
    println!("bitfield payload: {:?}", bitfield);

    // resp len=0, id=interested
    len_prefix = [0u8, 0u8, 0u8, 0u8];
    msg_id[0] = 2;
    stream.write_all(&len_prefix).expect("resp len failed");
    stream.write_all(&msg_id).expect("interested failed");
    println!("send interested");

    // rcv unchoke
    stream.read_exact(&mut len_prefix).expect("len failed");
    stream.read_exact(&mut msg_id).expect("id failed");
    message_length = u32::from_be_bytes(len_prefix) as usize;
    println!("unchoke len: {}, id: {}", message_length, msg_id[0]);

    // send 6:request to each downloader
    hashes.iter().enumerate().for_each(|(idx, chunk)| {
        // Break the piece into blocks of 16 kiB (16 * 1024 bytes)
        let begin = idx * CHUNK_SIZE;
        let length = if idx < bitfield.len() - 1 {
            CHUNK_SIZE
        } else {
            chunk.len()
        };
        let mut payload: Vec<u8> = Vec::new();
        let idx_32: u32 = idx.try_into().unwrap();
        let begin_32: u32 = begin.try_into().unwrap();
        let len_32: u32 = length.try_into().unwrap();
        payload.extend_from_slice(&idx_32.to_be_bytes());
        payload.extend_from_slice(&begin_32.to_be_bytes());
        payload.extend_from_slice(&len_32.to_be_bytes());

        let payload_len_32: u32 = payload.len().try_into().unwrap();
        let mut req_message: Vec<u8> = Vec::with_capacity(13);
        req_message.extend(payload_len_32.to_be_bytes()); // prefix len
        req_message.extend(vec![6].as_slice()); // 6=request
        req_message.extend(payload.as_slice()); // payload: selector=id,offset,len
        println!("sending request: {:?}", req_message);
        stream.write(req_message.as_slice()).expect("req failed");

        stream.read_exact(&mut len_prefix).expect("len failed");
        stream.read_exact(&mut msg_id).expect("id failed");
        let mut block: Vec<u8> = Vec::new();
        stream.read_to_end(&mut block).expect("block read failed");
        let block_hash = get_sha1(block.as_slice());
        let expected_hash = hashes[idx].clone();
        let same = block_hash == expected_hash;
        println!("{:?} == {:?} {}", block_hash, expected_hash, same);
        // save block to output fn
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(output_fn)
            .unwrap();
        file.write_all(block.as_slice()).unwrap();
    })
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
            let meta_info = read_torrent_info(filename).unwrap();
            let url = meta_info.announce;
            let len = meta_info.length;
            let info_hash = meta_info.info_hash;
            println!("Tracker URL: {url}");
            println!("Length: {len}");
            println!("Info Hash: {info_hash}");
            println!("Piece Length: {}", meta_info.piece_len);
            println!("Piece Hashes:");
            for hash in meta_info.piece_hashes {
                println!("{hash}");
            }
        }
        "peers" => {
            let filename = &args[2];
            let meta_info = read_torrent_info(filename).unwrap();
            let peer_info = read_peer_url(&meta_info).unwrap();
            for peer in fmt_ip_str(peer_info.peers) {
                println!("{}", peer);
            }
        }
        "handshake" => {
            let filename = &args[2];
            let meta_info = read_torrent_info(filename).unwrap();
            let ip_port = &args[3];
            let stream = TcpStream::connect(ip_port).expect("Failed to connect to peer");
            let peer_id = send_handshake(&stream, &meta_info.info_hash);
            println!("Peer ID: {}", peer_id);
        }
        "download_piece" => {
            // -o /tmp/test-piece-0 sample.torrent 0
            let output_fn = &args[3];
            let filename = &args[4];
            let idx = &args[5];
            let meta_info: MetaInfo = read_torrent_info(filename).unwrap();
            let peer_info = read_peer_url(&meta_info).unwrap();
            println!("{:?}", meta_info);
            for peer_ipaddr in fmt_ip_str(peer_info.peers) {
                println!("Connecting to: {:?}", peer_ipaddr);
                let stream = TcpStream::connect(peer_ipaddr).expect("Failed to connect to peer");
                let peer_id = send_handshake(&stream, &meta_info.info_hash);
                println!("Handshake Peer ID: {}", peer_id);
                download_piece(&stream, &meta_info.piece_hashes, output_fn);
                println!("Piece {} downloaded to {}", idx, output_fn);
            }
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
