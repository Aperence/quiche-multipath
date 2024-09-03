use log::{error, info, trace};
use ring::rand::SecureRandom;

pub const MAX_NUMBER_SOCKETS: usize = 20;

pub fn read_loop(events: &mio::Events, conn: &mut quiche::Connection, socket: &mio::net::UdpSocket, buf: &mut [u8]){
    'read: loop {
        if events.is_empty() {
            trace!("timed out");

            conn.on_timeout();

            break 'read;
        }

        let (len, from) = match socket.recv_from(buf) {
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

        let recv_info = quiche::RecvInfo {
            from,
            to: socket.local_addr().unwrap(),
        };

        let read = match conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(_) => {
                // An error occurred, handle it.
                break;
            },
        };

        info!("{} processed {} bytes", conn.trace_id(), read);
    }
}

pub fn write_loop(conn: &mut quiche::Connection, sockets: &Vec<mio::net::UdpSocket>, out: &mut [u8]){
    for i in (0..sockets.len()).rev(){
        let socket = &sockets[i];
        let local_addr = socket.local_addr().unwrap();
        // loop on different paths
        for peer_addr in conn.paths_iter(local_addr) {
            loop {
                let (write, send_info) = match conn.send_on_path(out, Some(local_addr), Some(peer_addr))
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", conn.trace_id(), e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(
                    &out[..write],
                    send_info.to
                ) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() would block");
                        break;
                    }

                    panic!("send_to() failed: {:?}", e);
                }

                info!("{} written {} bytes", conn.trace_id(), write);
            }
        }
    }
}

pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}
