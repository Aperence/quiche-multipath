use std::collections::HashMap;

#[macro_use]
extern crate log;

use quiche::{self, ConnectionId};
use quiche_test::shared::{generate_cid_and_reset_token, write_loop, MAX_NUMBER_SOCKETS};
use ring::rand::*;

const MAX_BUF_SIZE: usize = 65507;

struct Client{
    conn: quiche::Connection,
    id: u64
}

type ClientMap = HashMap<u64, Client>;
type ClientIDMap = HashMap<ConnectionId<'static>, u64>;

fn main() {
    let mut buf = [0; MAX_BUF_SIZE];
    let mut out = [0; MAX_BUF_SIZE];

    env_logger::builder().format_timestamp_nanos().init();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut sockets = vec![];
    for i in 0..MAX_NUMBER_SOCKETS{
        let port = 8000 + i;
        let mut socket = mio::net::UdpSocket::bind(format!("127.0.0.1:{port}").parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(i), mio::Interest::READABLE)
            .unwrap();
        sockets.push(socket);
    }

    info!("listening on {:}", sockets[0].local_addr().unwrap());

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.set_application_protos(&[b"http/0.9"]).unwrap();
    config.load_cert_chain_from_pem_file("src/bin/cert.crt").unwrap();
    config.load_priv_key_from_pem_file("src/bin/cert.key").unwrap();

    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    config.set_initial_max_data(1000000);
    config.set_initial_max_stream_data_bidi_local(1000000);
    config.set_initial_max_stream_data_bidi_remote(1000000);
    config.set_initial_max_stream_data_uni(1000000);

    config.set_active_connection_id_limit(20);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    let rng = SystemRandom::new();
    let _ =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut client_ids = ClientIDMap::new();
    let mut clients = ClientMap::new();

    let mut curr_id = 0;

    loop{
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            for event in &events{
                let socket = sockets.get(event.token().0).unwrap();
                let local_addr = socket.local_addr().unwrap();

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    },
                };

                let pkt_buf = &mut buf[..len];

                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(
                    pkt_buf,
                    quiche::MAX_CONN_ID_LEN,
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    },
                };

                let client = if !client_ids.contains_key(&hdr.dcid)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    rng.fill(&mut scid[..]).unwrap();
                    let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                    #[allow(unused_mut)]
                    let mut conn = quiche::accept(
                        &scid,
                        None,
                        local_addr,
                        from,
                        &mut config,
                    )
                    .unwrap();

                    if let Some(keylog) = &mut keylog {
                        if let Ok(keylog) = keylog.try_clone() {
                            conn.set_keylog(Box::new(keylog));
                        }
                    }

                    let id = curr_id;

                    client_ids.insert(scid.clone(), id);
                    clients.insert(id, Client{conn, id});
                    curr_id += 1;

                    clients.get_mut(&id).unwrap()
                } else {
                    let id = client_ids.get(&hdr.dcid).unwrap();
                    clients.get_mut(id).unwrap()
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue 'read;
                    },
                };

                info!("{} processed {} bytes", client.conn.trace_id(), read);
            }
        }

        for client in clients.values_mut() {

            handle_path_events(client);

            for stream_id in client.conn.readable() {
                // Stream is readable, read until there's no more data.
                while let Ok((read, fin)) = client.conn.stream_recv(stream_id, &mut buf) {
                    println!("Received {} on stream {}", std::str::from_utf8(&buf[..read]).unwrap(), stream_id);
                    client.conn.stream_send(stream_id, &buf[..read], fin).unwrap();
                }
            }

            while client.conn.scids_left() > 0 {
                let (scid, reset_token) = generate_cid_and_reset_token(&rng);
                if client.conn.new_scid(&scid, reset_token, false).is_err() {
                    break;
                }

                client_ids.insert(scid, client.id);
            }

            write_loop(&mut client.conn, &sockets, &mut out);
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if c.conn.is_closed() {
                println!("Closing connection to {}", c.conn.trace_id());

                info!(
                    "{} connection collected {:?} {:?}",
                    c.conn.trace_id(),
                    c.conn.stats(),
                    c.conn.path_stats().collect::<Vec<quiche::PathStats>>()
                );
            }

            !c.conn.is_closed()
        });
    }
}

fn handle_path_events(client: &mut Client) {
    while let Some(qe) = client.conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                info!(
                    "{} Seen new path ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );

                // Directly probe the new path.
                client
                    .conn
                    .probe_path(local_addr, peer_addr)
                    .expect("cannot probe");
            },

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    client.conn.trace_id(),
                    cid_seq,
                    old,
                    new
                );
            },

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                info!(
                    "{} Connection migrated to ({}, {})",
                    client.conn.trace_id(),
                    local_addr,
                    peer_addr
                );
            },
        }
    }
}
