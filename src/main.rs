mod utils;
use utils::*;

use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpStream};
use std::thread;

use bitcoin::consensus::encode::*;
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::util::hash::BitcoinHash;
use bitcoin_hashes::Hash;

fn communicate(addr: SocketAddr) {
    let mut stream = match TcpStream::connect(addr) {
        Err(_) => return,
        Ok(stream) => stream,
    };
    println!("Connected to {}", addr);

    let bytes_written = stream.write(&VERSION_BYTES).unwrap();
    println!("Done sending version ({} bytes)", bytes_written);

    let mut read_buffer = [0; 1500];
    let mut data = Vec::new();

    let mut satoshi_sum = 0;
    loop {
        let bytes_read = match stream.read(&mut read_buffer) {
            Err(error) => return,
            Ok(bytes_read) => bytes_read,
        };
        if bytes_read == 0 {
            continue;
        }
        data.extend_from_slice(&read_buffer[0..bytes_read]);
        let header_length = 24;
        if data.len() < header_length {
            continue;
        }
        let payload_width = combine_u32(&data[16..20]);
        let message_length = header_length + payload_width as usize;
        if data.len() < message_length {
            continue;
        }

        let mut cursor = Cursor::new(data.clone());
        match RawNetworkMessage::consensus_decode(&mut cursor) {
            Err(error) => {
                eprintln!("Decode error {}", error);
            }
            Ok(message) => match message.payload {
                NetworkMessage::Verack => {
                    println!("Confirm handshake with {}", addr);
                    let getheaders_bytes = make_getheaders_bytes(&GENESIS_HASH);
                    stream.write(&getheaders_bytes).unwrap();
                    println!("Sent getheaders");
                }
                NetworkMessage::Headers(headers) => {
                    println!("Received {:?} headers", headers.len());
                    for header in headers {
                        let block_hash = header.header.bitcoin_hash();
                        let getdata = make_getdata_bytes(&block_hash.into_inner());
                        stream.write(&getdata).unwrap();
                    }
                }
                NetworkMessage::Block(block) => {
                    println!("Received block {}", block.bitcoin_hash());
                    let value = block.txdata[0].output[0].value;
                    satoshi_sum += value;
                    println!(
                        "As of {}, satoshi has {}",
                        block.header.time,
                        satoshi_sum / 100000000
                    )
                }
                NetworkMessage::Version(version) => {
                    stream.write(&VERACK_BYTES).unwrap();
                }
                _ => println!("Unprocessed payload"),
            },
        }

        data = data[message_length..].to_vec();
    }
}

fn main() {
    let addrs: Vec<_> = SEEDS
        .iter()
        .map(|seed| seed.to_socket_addrs().unwrap())
        .flatten()
        .collect();
    println!("addrs : {:?}", addrs);

    let connections: Vec<_> = addrs
        .into_iter()
        .map(|addr| thread::spawn(move || communicate(addr)))
        .collect();

    for connection in connections {
        connection.join();
    }
}
