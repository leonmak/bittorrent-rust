/*
pub announce: URL to a "tracker", which is a central server that keeps track of peers participating in the sharing of a torrent.
pub info: A dictionary with pub keys:
    pub length: size of the file in bytes, for single-file torrents
    pub name: suggested name to save the file / directory as
    piece pub length: number of bytes in each piece
    pub pieces: concatenated SHA-1 hashes of each piece
 */

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct MetaInfo {
    pub announce: String,
    pub length: String,
    pub info_hash: String,
    pub piece_len: String,
    pub piece_hashes: Vec<String>,
}

pub struct HelperInfo {
    pub info_start: usize,
    pub info_end: usize,
    pub found_info_start: bool,
    pub is_bytes_val: bool,
}

impl HelperInfo {
    pub fn new() -> Self {
        HelperInfo {
            info_start: 1, // exclude first d
            info_end: 0,
            found_info_start: false,
            is_bytes_val: false,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PeerInfo {
    pub interval: u64,
    pub peers: Vec<u8>,
}

#[derive(Debug)]
pub struct HandshakeMessage {
    pub pstr_len: u8,
    pub pstr: [u8; 19],
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

pub fn read_handshake_message<R: std::io::Read>(
    reader: &mut R,
) -> std::io::Result<HandshakeMessage> {
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

// xt: urn:btih: followed by the 40-char hex-encoded info hash (example: urn:btih:d69f91e6b2ae4c542468d1073a71d4ea13879a7f)
// dn: The name of the file to be downloaded (example: sample.torrent)
// tr: The tracker URL (example: http://bittorrent-test-tracker.codecrafters.io/announce)
pub struct MagnetLinkParams {
    pub exact_topic: String,
    pub info_hash: String,
    pub download_name: String,
    pub tracking_url: String,
}

// magnet:?xt=urn:btih:d69f91e6b2ae4c542468d1073a71d4ea13879a7f&dn=sample.torrent&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce
pub fn parse_magnet_uri(uri: &String) -> MagnetLinkParams {
    let mut xt = String::new();
    let mut xt_info = String::new();
    let mut dn = String::new();
    let mut tr = String::new();

    let parts: Vec<&str> = uri.split('?').collect();
    if parts.len() > 1 {
        let queries: Vec<&str> = parts[1].split('&').collect();
        for query in queries {
            let kv: Vec<&str> = query.split('=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "xt" => {
                        xt = kv[1].to_string();
                        xt_info = kv[1].split("urn:btih:").collect::<Vec<&str>>()[1].to_string();
                    }
                    "dn" => dn = kv[1].to_string(),
                    "tr" => tr = kv[1].to_string(),
                    _ => {}
                }
            }
        }
    }

    MagnetLinkParams {
        exact_topic: xt,
        info_hash: xt_info,
        download_name: dn,
        tracking_url: tr,
    }
}
