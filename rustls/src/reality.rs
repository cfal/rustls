//! Connection-scoped integration points for the REALITY TLS 1.3 transport.
//!
//! These APIs do not authenticate REALITY peers. The caller must supply the
//! authentication and certificate policy. Ordinary TLS connections never use them.

use alloc::boxed::Box;
use core::fmt::Debug;

use crate::Error;
use crate::crypto::{ActiveKeyExchange, SupportedKxGroup};

/// State owned by exactly one REALITY client connection.
///
/// Implementations must not print private keys or authentication material in Debug.
pub trait ClientHooks: Debug + Send + Sync {
    /// Start the TLS exchange and derive any additional REALITY authentication
    /// secret without consuming the exchange. The returned group must match `group`.
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error>;

    /// Authenticate the final encoded ClientHello by replacing only its 32-byte
    /// legacy session ID. `hello` includes the handshake header, not a record header.
    /// Rustls updates both the encoded hello and its retained session-ID state.
    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error>;

    /// Capture the exact finalized hello messages before certificate verification.
    /// Both slices include handshake headers and exclude record headers.
    fn server_hello(&mut self, client: &[u8], server: &[u8]) -> Result<(), Error>;
}

pub(crate) fn incompatible() -> Error {
    crate::PeerIncompatible::RealityUnsupported.into()
}
