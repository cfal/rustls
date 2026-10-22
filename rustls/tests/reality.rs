#![allow(clippy::disallowed_types)]

use std::sync::{Arc, Mutex};

use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::ServerName;
use rustls::reality::ClientHooks;
use rustls::{ClientConnection, Error, ServerConnection};
use rustls_test::{KeyType, do_handshake, make_client_config_with_versions, make_server_config};

#[derive(Debug, Default)]
struct HelloCapture {
    client: Vec<u8>,
    server: Vec<u8>,
}

#[derive(Debug)]
struct Hooks(Arc<Mutex<HelloCapture>>);

impl ClientHooks for Hooks {
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        group.start()
    }

    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error> {
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 32);
        Ok([0xa7; 32])
    }

    fn server_hello(&mut self, client: &[u8], server: &[u8]) -> Result<(), Error> {
        let mut capture = self.0.lock().unwrap();
        capture.client = client.to_vec();
        capture.server = server.to_vec();
        Ok(())
    }
}

#[test]
fn finalized_session_id_and_exact_hello_context_complete_handshake() {
    let provider = aws_lc_rs::default_provider();
    let config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    let capture = Arc::new(Mutex::new(HelloCapture::default()));
    let mut client = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(capture.clone())),
    )
    .unwrap();
    let mut server =
        ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa2048, &provider))).unwrap();
    let mut client_wire = Vec::new();
    client
        .write_tls(&mut client_wire)
        .unwrap();
    assert_eq!(&client_wire[44..76], &[0xa7; 32]);
    server
        .read_tls(&mut client_wire.as_slice())
        .unwrap();
    server.process_new_packets().unwrap();
    let mut server_wire = Vec::new();
    server
        .write_tls(&mut server_wire)
        .unwrap();
    let server_hello_len = u16::from_be_bytes([server_wire[3], server_wire[4]]) as usize;
    let mut remaining = server_wire.as_slice();
    while !remaining.is_empty() {
        assert!(client.read_tls(&mut remaining).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
    do_handshake(&mut client, &mut server);
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    let capture = capture.lock().unwrap();
    assert_eq!(capture.client, client_wire[5..]);
    assert_eq!(capture.server, server_wire[5..5 + server_hello_len]);
}

#[test]
fn reality_rejects_tls12_configuration() {
    let provider = aws_lc_rs::default_provider();
    let config = rustls_test::make_client_config(KeyType::Rsa2048, &provider);
    let result = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(Arc::default())),
    );
    assert!(matches!(
        result,
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::RealityUnsupported
        ))
    ));
}

#[test]
fn reality_rejects_wrong_session_id_echo() {
    let provider = aws_lc_rs::default_provider();
    let config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    let mut client = ClientConnection::new_reality(
        Arc::new(config),
        ServerName::try_from("localhost").unwrap(),
        Box::new(Hooks(Arc::default())),
    )
    .unwrap();
    let mut server =
        ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa2048, &provider))).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server
        .read_tls(&mut wire.as_slice())
        .unwrap();
    server.process_new_packets().unwrap();
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    wire[44] ^= 1;
    client
        .read_tls(&mut wire.as_slice())
        .unwrap();
    assert!(matches!(
        client.process_new_packets(),
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::RealityUnsupported
        ))
    ));
}
