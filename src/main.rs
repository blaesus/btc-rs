mod utils;

use std::collections::HashMap;
use std::io::{Cursor, Error, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;

use bitcoin::consensus::encode::{Decodable, Encodable};
use bitcoin::network::message::NetworkMessage;
use bitcoin::util::hash::BitcoinHash;

use crate::utils::{
    combine_u32, dsha256, pretty_dump, seeds, serialize_u32, GENESIS_HASH, VERACK_BYTES,
    VERSION_BYTES,
};

type KeyValueMap = HashMap<Vec<u8>, Vec<u8>>;

fn make_message_bytes(command: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&[0xf9, 0xbe, 0xb4, 0xd9]);
    result.extend_from_slice(command);
    result.extend_from_slice(&serialize_u32(payload.len() as u32));
    result.extend_from_slice(&dsha256(payload)[0..4]);
    result.extend_from_slice(payload);
    return result;
}

fn extract_command(bytes: &[u8]) -> String {
    let mut s = 4;
    while bytes[s] != 0 {
        s += 1
    }
    let command_bytes = &bytes[4..s];
    String::from_utf8_lossy(command_bytes).into()
}

fn make_getheaders_bytes(target: &[u8]) -> Vec<u8> {
    let command = "getheaders\0\0".as_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x7f, 0x11, 0x01, 0x00]);
    payload.push(0x01);
    payload.extend_from_slice(target);
    let filler: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    payload.extend_from_slice(&filler);
    let bytes = make_message_bytes(&command, &payload);
    return bytes;
}

fn make_getdata_bytes(target: &[u8]) -> Vec<u8> {
    let command = "getdata\0\0\0\0\0".as_bytes();
    let mut payload = Vec::new();
    payload.push(0x01);
    payload.extend_from_slice(&[0x02, 0, 0, 0]);
    payload.extend_from_slice(target);
    let bytes = make_message_bytes(&command, &payload);
    return bytes;
}

fn communicate(addr: SocketAddr) {
    let mut stream = match TcpStream::connect(addr) {
        Err(error) => return,
        Ok(stream) => stream,
    };
    println!("Connected to {}", addr);
    let version_bytes = VERSION_BYTES;
    stream.write(&version_bytes).unwrap();

    let mut buffer = [0; 1500];
    let mut data: Vec<u8> = Vec::new();
    let mut expected_data_length: u32 = 0;
    loop {
        match stream.read(&mut buffer) {
            Err(error) => eprintln!("Read failed {}", error),
            Ok(bytes_read) => {
                if bytes_read > 0 {
                    data.extend_from_slice(&buffer[0..bytes_read]);
                }
            }
        }
        if data.len() < 4 {
            continue;
        }
        let payload_width = combine_u32([data[16], data[17], data[18], data[19]]);
        let message_width = payload_width + 24;
        let data_ready = data.len() >= message_width as usize;
        if data_ready {
            let mut cursor = Cursor::new(&data);
            match bitcoin::network::message::RawNetworkMessage::consensus_decode(&mut cursor) {
                Err(err) => {
                    println!("Cannot parse {}", err);
                }
                Ok(message) => match message.payload {
                    NetworkMessage::Verack => {
                        println!("Received verack");
                        let request = make_getheaders_bytes(&GENESIS_HASH);
                        println!("sending");
                        pretty_dump(&request);
                        let write_size = stream.write(&request).unwrap();
                    }
                    NetworkMessage::Version(version) => {
                        println!("Received version;");
                        stream.write(&VERACK_BYTES).unwrap();
                    }
                    NetworkMessage::Headers(headers) => {
                        println!("Received headers");
                        let count = 2000;
                        for i in 0..count {
                            let start = 24 + 3 + i * 81;
                            let end = start + 81;
                            let seg = &data[start..end];
                            let header = &seg[0..80];
                            let hash = dsha256(&header);
                            let get_data = make_getdata_bytes(&hash);
                            pretty_dump(&get_data);
                            stream.write(&get_data).unwrap();
                        }
                    }
                    NetworkMessage::Block(block) => {
                        let output = &block.txdata[0].output[0];
                        println!(
                            "block {}, output = {}",
                            block.header.bitcoin_hash(),
                            output.value
                        )
                    }
                    _ => eprintln!("Unprocessed"),
                },
            }
            data = data[message_width as usize..].to_vec()
        }
    }
}

fn main() {
    let addresses: Vec<_> = seeds
        .iter()
        .map(|s| s.to_socket_addrs().unwrap())
        .flatten()
        .collect();

    println!("Collected {} addresses", addresses.len());

    let handles: Vec<_> = addresses
        .into_iter()
        .map(|addr| thread::spawn(move || communicate(addr)))
        .collect();

    for handle in handles {
        handle.join().unwrap()
    }
}
