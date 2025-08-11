//! A minimal DKIM signing library for Rust.

// Module declarations
pub mod common;
pub mod dkim;

// Re-export the main signer struct and other necessary components.
pub use dkim::{DkimSigner, Signature};
pub use common::crypto::{RsaKey, Sha256};
pub use common::headers::HeaderWriter;

/// A simplified function to sign an email with an RSA-SHA256 DKIM signature.
///
/// # Arguments
///
/// * `email` - The full email content (headers and body) as a string slice.
/// * `domain` - The signing domain (e.g., "example.com").
/// * `selector` - The DKIM selector (e.g., "default").
/// * `private_key` - The RSA private key in PKCS#1 PEM format.
///
/// # Returns
///
/// A `String` containing the DKIM signature header prepended to the original email.
pub fn sign_email(email: &str, domain: &str, selector: &str, private_key: &str) -> String {
    // Sign an e-mail message using RSA-SHA256
    let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(private_key).unwrap();
    let signature_rsa = DkimSigner::from_key(pk_rsa)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject"])
        .sign(email.as_bytes())
        .unwrap();

    format!("{}{}", signature_rsa.to_header(), email)
}


/// A minimal error type for the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NoHeadersFound,
    CryptoError(String),
    Base64,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoHeadersFound => write!(f, "No headers found to sign"),
            Error::CryptoError(err) => write!(f, "Cryptography error: {err}"),
            Error::Base64 => write!(f, "Base64 encoding error."),
        }
    }
}

// Convert from rsa::errors::Error to our custom Error type.
impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}
