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

fn target_hello(
    provider: &rustls::crypto::CryptoProvider,
) -> (ClientConnection, rustls::ServerConfig, Vec<u8>, Vec<u8>) {
    let config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], provider);
    let server_config = rustls_test::make_server_config_with_versions(
        KeyType::Ed25519,
        &[&rustls::version::TLS13],
        provider,
    );
    let mut client =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut target = ServerConnection::new(Arc::new(server_config.clone())).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        assert!(target.read_tls(&mut remaining).unwrap() > 0);
        target.process_new_packets().unwrap();
    }
    let mut response = Vec::new();
    target.write_tls(&mut response).unwrap();
    let len = u16::from_be_bytes([response[3], response[4]]) as usize;
    (client, server_config, wire, response[5..5 + len].to_vec())
}

fn mask_key_share(hello: &[u8]) -> Vec<u8> {
    let mut masked = hello.to_vec();
    let mut offset = 44 + usize::from(hello[38]);
    while offset < hello.len() {
        let typ = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        if typ == 51 {
            masked[offset + 8..offset + 4 + len].fill(0);
        }
        offset += 4 + len;
    }
    masked
}

#[test]
fn prepared_server_hello_preserves_target_and_completes_all_suites_and_groups() {
    for group in [
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::X25519MLKEM768,
    ] {
        for suite in aws_lc_rs::default_provider()
            .cipher_suites
            .into_iter()
            .filter(|s| s.tls13().is_some())
        {
            for reverse in [false, true] {
                let provider = rustls::crypto::CryptoProvider {
                    cipher_suites: vec![suite],
                    kx_groups: vec![group],
                    ..aws_lc_rs::default_provider()
                };
                let (mut client, server_config, client_wire, mut template) =
                    target_hello(&provider);
                if reverse {
                    let offset = 44 + usize::from(template[38]);
                    let len =
                        u16::from_be_bytes([template[offset + 2], template[offset + 3]]) as usize;
                    template[offset..].rotate_left(4 + len);
                }
                let prepared = rustls::reality::PreparedServerHello::new(
                    &client_wire[5..],
                    &template,
                    &provider,
                )
                .unwrap();
                assert_eq!(
                    mask_key_share(prepared.server_hello()),
                    mask_key_share(&template)
                );
                assert_ne!(prepared.server_hello(), template);
                assert_eq!(prepared.cipher_suite(), suite.suite());
                assert_eq!(prepared.group(), group.name());
                let final_hello = prepared.server_hello().to_vec();
                let mut server =
                    ServerConnection::new_reality(Arc::new(server_config), prepared).unwrap();
                let mut remaining = client_wire.as_slice();
                while !remaining.is_empty() {
                    server.read_tls(&mut remaining).unwrap();
                    server.process_new_packets().unwrap();
                }
                let mut response = Vec::new();
                server.write_tls(&mut response).unwrap();
                assert_eq!(&response[5..5 + final_hello.len()], final_hello);
                let mut remaining = response.as_slice();
                while !remaining.is_empty() {
                    assert!(client.read_tls(&mut remaining).unwrap() > 0);
                    client.process_new_packets().unwrap();
                }
                do_handshake(&mut client, &mut server);
                assert_eq!(client.negotiated_cipher_suite(), Some(suite));
            }
        }
    }
}

#[test]
fn prepared_hello_rejects_unsupported_template_and_client_substitution() {
    let provider = aws_lc_rs::default_provider();
    let (_, server_config, client_wire, template) = target_hello(&provider);
    for offset in [0, 1, 4, 39] {
        let mut bad = template.clone();
        bad[offset] ^= 1;
        assert!(
            rustls::reality::PreparedServerHello::new(&client_wire[5..], &bad, &provider).is_err()
        );
    }
    let prepared =
        rustls::reality::PreparedServerHello::new(&client_wire[5..], &template, &provider).unwrap();
    let mut server = ServerConnection::new_reality(Arc::new(server_config), prepared).unwrap();
    let mut different_client = client_wire;
    different_client[11] ^= 1;
    server
        .read_tls(&mut different_client.as_slice())
        .unwrap();
    assert!(server.process_new_packets().is_err());
}

fn record_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut remaining = wire;
    while !remaining.is_empty() {
        let len = 5 + u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
        lengths.push(len);
        remaining = &remaining[len..];
    }
    lengths
}

#[test]
fn shaped_flights_preserve_record_lengths_and_application_key_epoch() {
    use std::io::{Read, Write};
    for suite in aws_lc_rs::default_provider()
        .cipher_suites
        .into_iter()
        .filter(|s| s.tls13().is_some())
    {
        for lengths in [vec![4096], vec![64, 4096, 128, 80]] {
            for trailing in [None, Some(128)] {
                let provider = rustls::crypto::CryptoProvider {
                    cipher_suites: vec![suite],
                    ..aws_lc_rs::default_provider()
                };
                let (mut client, config, client_wire, template) = target_hello(&provider);
                let plan = rustls::reality::FlightPlan::new(&lengths, trailing).unwrap();
                let prepared = rustls::reality::PreparedServerHello::new(
                    &client_wire[5..],
                    &template,
                    &provider,
                )
                .unwrap()
                .with_flight_plan(plan);
                let mut server = ServerConnection::new_reality(Arc::new(config), prepared).unwrap();
                let mut remaining = client_wire.as_slice();
                while !remaining.is_empty() {
                    assert!(server.read_tls(&mut remaining).unwrap() > 0);
                    server.process_new_packets().unwrap();
                }
                let mut wire = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut wire).unwrap();
                }
                let mut expected = vec![template.len() + 5, 6];
                expected.extend(&lengths);
                expected.extend(trailing);
                assert_eq!(record_lengths(&wire), expected);
                let mut remaining = wire.as_slice();
                while !remaining.is_empty() {
                    assert!(client.read_tls(&mut remaining).unwrap() > 0);
                    client.process_new_packets().unwrap();
                }
                do_handshake(&mut client, &mut server);
                server.refresh_traffic_keys().unwrap();
                server
                    .writer()
                    .write_all(b"after key update")
                    .unwrap();
                rustls_test::transfer(&mut server, &mut client);
                client.process_new_packets().unwrap();
                let mut received = [0; 16];
                client
                    .reader()
                    .read_exact(&mut received)
                    .unwrap();
                assert_eq!(&received, b"after key update");
            }
        }
    }
}
