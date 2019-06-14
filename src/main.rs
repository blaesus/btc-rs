use crate::utils::*;
use std::io::{Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpStream};
use std::thread;

use bitcoin::consensus::encode::*;
use bitcoin::network::message::*;
use bitcoin::util::hash::BitcoinHash;
use bitcoin_hashes::Hash;

mod utils;

fn communicate(addr: SocketAddr) {
    match TcpStream::connect(addr) {
        Err(error) => eprintln!("Connection error {}", error),
        Ok(mut stream) => {
            println!("Connected to {}", addr);
            stream.write(&VERSION_BYTES).unwrap();
            println!("VERSION Sent!");

            let mut read_buffer = [0; 1500];
            let mut data = Vec::new();
            loop {
                let bytes_read = stream.read(&mut read_buffer).unwrap();
                if bytes_read > 0 {
                    data.extend_from_slice(&read_buffer[0..bytes_read])
                }

                let message_header_length = 24;

                if data.len() < message_header_length {
                    continue;
                }

                let payload_length = combine_u32(&data[16..20]);
                let message_length = message_header_length + payload_length as usize;

                if data.len() < message_length {
                    continue;
                }

                // data is ready
                let mut cursor = Cursor::new(&data);
                match RawNetworkMessage::consensus_decode(&mut cursor) {
                    Err(error) => eprintln!("parsing error {}", error),
                    Ok(raw_message) => match raw_message.payload {
                        NetworkMessage::Verack => {
                            println!("Handshake ok");
                            let getheaders_msg = make_getheaders_bytes(&GENESIS_HASH);
                            stream.write(&getheaders_msg).unwrap();
                            println!("sent getheaders")
                        }
                        NetworkMessage::Headers(headers) => {
                            println!("Get {} headers", headers.len());
                            for header in headers {
                                let block_hash = header.header.bitcoin_hash();
                                let getdata_msg = make_getdata_bytes(&block_hash.into_inner());
                                stream.write(&getdata_msg).unwrap();
                            }
                        }
                        NetworkMessage::Block(block) => {
                            println!("Get block {}", block.bitcoin_hash());
                            block
                                .txdata
                                .iter()
                                .for_each(|tx| println!("Tx ouput: {:?}", tx.output[0].value));
                        }
                        NetworkMessage::Version(version) => {
                            stream.write(&VERACK_BYTES).unwrap();
                        }
                        _ => println!("Received unprocessed message payload"),
                    },
                }

                data = data[message_length..].to_vec();
            }
        }
    }
}

fn main() {
    let peers_addrs: Vec<_> = SEEDS
        .iter()
        .map(|seed| seed.to_socket_addrs().unwrap())
        .flatten()
        .collect();

    println!("peers {:#?}", peers_addrs);

    let handles: Vec<_> = peers_addrs
        .into_iter()
        .map(|addr| thread::spawn(move || communicate(addr)))
        .collect();

    for handle in handles {
        handle.join();
    }
}
