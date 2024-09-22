mod structs;
mod utils;

use anyhow::Error;
use reqwest::blocking::get;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::fmt::Write;
use std::fs::File;
use std::io::{Cursor, Write as _};
use std::net::TcpStream;
use std::time::Duration;
use std::{env, fs, path::Path};
use structs::{parse_magnet_uri, read_handshake_message, HelperInfo, MetaInfo, PeerInfo};
use urlencoding::decode;
use utils::decode_bencoded_value;

// https://www.bittorrent.org/beps/bep_0003.html
fn read_torrent_info(filename: &str) -> Option<MetaInfo> {
    let path = Path::new(filename);
    match fs::read(path) {
        Ok(encoded_value) => {
            let mut helper = HelperInfo::new();
            let (decoded_value, _len) =
                decode_bencoded_value(encoded_value.as_slice(), &mut helper);

            let url = decoded_value.get("announce")?.to_string();
            let info_dict = decoded_value.get("info")?.clone();
            let length = info_dict.get("length")?.to_string();
            let info_dict_slice = &encoded_value[helper.info_start..helper.info_end];

            let piece_len = info_dict.get("piece length")?.to_string();
            let piece_hashes = info_dict.get("pieces")?.as_array()?.clone();
            let meta_info = MetaInfo {
                announce: remove_json_quote(url),
                length,
                info_hash: get_sha1(info_dict_slice),
                piece_len,
                piece_hashes: pieces_sha1(piece_hashes),
            };
            // println!("debug {:?}", meta_info);
            Some(meta_info)
        }
        Err(e) => {
            println!("Read failed: {:?}", e);
            return None;
        }
    }
}

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

fn fmt_ip_str(ip_str: &Vec<u8>) -> Vec<String> {
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

use std::io::Read as _;
fn send_handshake(mut stream: &TcpStream, info_hash: &str) -> Result<String, Error> {
    // send a message with TCP
    let peer_id = "00112233445566778899"; // My Peer ID (20 bytes)

    let mut handshake_msg: Vec<u8> = Vec::new();
    handshake_msg.push(19); // Length of the protocol string (1 byte)
    handshake_msg.extend_from_slice(b"BitTorrent protocol"); // Protocol string (19 bytes)
    handshake_msg.extend_from_slice(&[0u8; 8]); // Reserved bytes (8 bytes)
    handshake_msg.extend_from_slice(hex_str_as_bytes(info_hash).as_slice()); // Info hash (20 bytes)
    handshake_msg.extend_from_slice(peer_id.as_bytes()); // Peer ID (20 bytes)
    println!("Handshake {} bytes", handshake_msg.len());
    // Send the handshake message
    stream
        .write_all(&handshake_msg)
        .expect("Failed to send handshake");

    // Read the response from the peer
    let mut response = [0u8; 68];
    stream.read_exact(&mut response)?;

    let mut cursor = Cursor::new(response);
    let handshake = read_handshake_message(&mut cursor).expect("Failed to read handshake message");
    Ok(format!(
        "{}",
        handshake.peer_id.map(|f| format!("{:02x}", f)).join("")
    ))
}

fn send_interested_message(stream: &mut TcpStream) -> std::io::Result<()> {
    let interested_msg = [0, 0, 0, 1, 2]; // <len=0001><id=2>
    stream.write_all(&interested_msg)?;
    Ok(())
}

fn send_request_message(
    stream: &mut TcpStream,
    piece_index: usize,
    block_offset: u64,
    block_length: u64,
) -> std::io::Result<()> {
    let mut request_msg = Vec::with_capacity(17);
    request_msg.extend_from_slice(&(13u32).to_be_bytes()); // <len=0013>
    request_msg.push(6); // <id=6>
    request_msg.extend_from_slice(&(piece_index as u32).to_be_bytes()); // <index>
    request_msg.extend_from_slice(&(block_offset as u32).to_be_bytes()); // <begin>
    request_msg.extend_from_slice(&(block_length as u32).to_be_bytes()); // <length>
    stream.write_all(&request_msg)?;
    Ok(())
}

const CHUNK_SIZE: u64 = 16384;
fn download_piece(
    mut stream: &mut TcpStream,
    meta_info: &MetaInfo,
    piece_idx: usize,
    piece_size: u64,
) -> Result<Vec<u8>, std::io::Error> {
    let expect_hash = meta_info.piece_hashes[piece_idx as usize].as_str();

    // message = length prefix (4 bytes), message id (1 byte), payload (variable size)
    let mut len_prefix = [0u8; 4];
    let mut msg_id = [0u8; 1];

    let mut piece_buf = vec![0u8; piece_size as usize];
    let mut num_chunks: u64 = 0;

    loop {
        // Read the length prefix (4 bytes)
        stream.read_exact(&mut len_prefix)?;
        // Read the message ID (1 byte)
        stream.read_exact(&mut msg_id)?;

        let payload_len = u32::from_be_bytes(len_prefix) as usize;
        // println!("msgid:{}, length:{}", msg_id[0], payload_len);
        // https://wiki.theory.org/BitTorrentSpecification#Messages

        match msg_id[0] {
            0 => {
                // Choke message
                println!("Peer choked us, waiting");
            }
            1 => {
                // Unchoke message
                println!("Peer unchoked us, sending request");
                // 1 piece contains many chunks/blocks, send a request per block
                num_chunks = piece_size / (CHUNK_SIZE as u64);
                let rem_size = piece_size % CHUNK_SIZE;
                if rem_size > 0 {
                    num_chunks += 1;
                }
                for chunk_idx in 0..num_chunks {
                    let piece_begin = CHUNK_SIZE * (chunk_idx as u64);
                    let odd_chunk = chunk_idx == num_chunks - 1 && rem_size > 0;
                    let chunk_len = if odd_chunk { rem_size } else { CHUNK_SIZE };
                    let res = send_request_message(&mut stream, piece_idx, piece_begin, chunk_len);
                    if res.is_ok() {
                        // println!(
                        //     "Sent Request #{}, offset {}, chunk_len {}",
                        //     chunk_idx, piece_begin, chunk_len
                        // );
                    } else {
                        eprint!("{}", res.err().unwrap());
                    }
                }
                println!("Sent {} chunk requests", num_chunks)
            }
            5 => {
                // Bitfield message
                let mut bitfield = vec![0u8; payload_len - 1];
                stream.read_exact(&mut bitfield)?;
                println!("Received bitfield: {:?}", bitfield);
                send_interested_message(&mut stream)?;
            }
            7 => {
                // Accumulate message chunks, until all chunks for piece received
                let mut idx_buf = [0u8; 4];
                let mut begin_buf = [0u8; 4];
                let chunk_len = payload_len - 9;
                let mut chunk_buf = vec![0u8; chunk_len];
                num_chunks -= 1;

                stream.read_exact(&mut idx_buf)?;
                stream.read_exact(&mut begin_buf)?;
                let _chunk_idx = u32::from_be_bytes(idx_buf) as usize;
                let offset_idx = u32::from_be_bytes(begin_buf) as usize;
                // println!(
                //     "chunk left {} , offset {}, chunk_len {}",
                //     num_chunks, offset_idx, chunk_len
                // );
                stream.read_exact(&mut chunk_buf)?;
                for (i, b) in chunk_buf.iter().enumerate() {
                    piece_buf[offset_idx + i] = *b;
                }
                println!("Received chunk length {}", chunk_buf.len());
                if num_chunks == 0 {
                    let dl_piece_hash = get_sha1(&piece_buf);
                    if expect_hash != dl_piece_hash {
                        panic!("Piece hash is not matching")
                    }
                    return Ok(piece_buf);
                }
            }
            _ => {
                // Ignore other messages for now
                let mut payload = vec![0u8; payload_len];
                stream.read_exact(&mut payload)?;
                eprint!("Failed to read msg")
            }
        }
    }
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
            for peer in fmt_ip_str(&peer_info.peers) {
                println!("{}", peer);
            }
        }
        "handshake" => {
            let filename = &args[2];
            let meta_info = read_torrent_info(filename).unwrap();
            let ip_port = &args[3];
            let stream = TcpStream::connect(ip_port).expect("Failed to connect to peer");
            match send_handshake(&stream, &meta_info.info_hash) {
                Ok(peer_id) => println!("Peer ID: {}", peer_id),
                Err(e) => println!("Error: {}", e),
            }
        }
        "download_piece" => {
            // -o /tmp/test-piece-0 sample.torrent 0
            let output_fn = &args[3];
            let filename = &args[4];
            let piece_idx = usize::from_str_radix(&args[5], 10).unwrap();
            let meta_info: MetaInfo = read_torrent_info(filename).unwrap();
            let peer_info = read_peer_url(&meta_info).unwrap();
            println!("{:?}", meta_info);
            let file_len = u64::from_str_radix(meta_info.length.as_str(), 10).unwrap();
            let num_pieces = meta_info.piece_hashes.len();
            let is_last_piece = piece_idx == num_pieces - 1;
            let mut piece_size = u64::from_str_radix(meta_info.piece_len.as_str(), 10).unwrap();
            if is_last_piece {
                piece_size = file_len % piece_size;
            }
            let peer_ips = fmt_ip_str(&peer_info.peers);
            for peer_ipaddr in peer_ips {
                println!("Connecting to: {:?}", peer_ipaddr);
                let stream_res = TcpStream::connect(peer_ipaddr);
                if stream_res.is_err() {
                    eprint!("Failed connect, {}", stream_res.err().unwrap());
                    continue;
                }
                let mut stream = stream_res.unwrap();
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let peer_id = send_handshake(&stream, &meta_info.info_hash);
                if peer_id.is_err() {
                    eprint!("Failed handshake, {}", peer_id.err().unwrap());
                    continue;
                }
                println!("Handshake Peer ID: {}", peer_id.unwrap());
                let res = download_piece(&mut stream, &meta_info, piece_idx, piece_size);
                if res.is_ok() {
                    println!("Piece {:?} downloaded to {}.", piece_idx, output_fn);
                    let mut file = File::create(output_fn).unwrap();
                    let piece_buf = res.unwrap();
                    file.write_all(&piece_buf).unwrap();
                    println!("Downloaded piece {} to {}", piece_idx + 1, output_fn);
                } else {
                    eprint!("Failed download, {}", res.err().unwrap());
                }
            }
        }
        "download" => {
            // -o /tmp/test-piece-0 sample.torrent
            let output_fn = &args[3];
            let filename = &args[4];
            let meta_info: MetaInfo = read_torrent_info(filename).unwrap();
            let file_size = u64::from_str_radix(&meta_info.length, 10).unwrap();
            let piece_size = u64::from_str_radix(&meta_info.piece_len, 10).unwrap();
            let mut file_buf = Vec::with_capacity(file_size as usize);
            println!("{:?}", meta_info);
            let peer_info = read_peer_url(&meta_info).unwrap();
            let num_pieces = meta_info.piece_hashes.len();
            println!("Downloading {} pieces", num_pieces);

            for piece_idx in 0..num_pieces {
                println!("# Fetching piece #{}", piece_idx + 1);
                for peer_ipaddr in fmt_ip_str(&peer_info.peers) {
                    let stream_res = TcpStream::connect(peer_ipaddr);
                    let mut stream = stream_res.unwrap();
                    let peer_id = send_handshake(&stream, &meta_info.info_hash);
                    let piece_size = if piece_idx == num_pieces - 1 {
                        file_size % piece_size
                    } else {
                        piece_size
                    };
                    println!("{:?}", peer_id);
                    let res = download_piece(&mut stream, &meta_info, piece_idx, piece_size);
                    if res.is_ok() {
                        file_buf.extend_from_slice(res.unwrap().as_slice());
                        println!("Downloaded piece {}\n", piece_idx + 1);
                        break;
                    } else {
                        eprintln!("Failed download #{}, {}", piece_idx + 1, res.err().unwrap());
                    }
                }
            }
            let mut file = File::create(output_fn).unwrap();
            file.write_all(&file_buf.as_slice()).unwrap();
            println!("Downloaded file {}", output_fn);
        }
        "magnet_parse" => {
            let magnet_uri = &args[2];
            let magnet_params = parse_magnet_uri(magnet_uri);
            // Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
            // Info Hash: d69f91e6b2ae4c542468d1073a71d4ea13879a7f
            println!(
                "Tracker URL: {}",
                decode(magnet_params.tracking_url.as_str()).expect("UTF-8")
            );
            println!("Info Hash: {}", magnet_params.info_hash);
        }
        _ => {
            println!("unknown command: {}", args[1])
        }
    }
}
