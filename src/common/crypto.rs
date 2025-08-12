use super::headers::{Writable, Writer};
use crate::Result;
use rsa::{pkcs1::DecodeRsaPrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use sha2::digest::Digest;
use std::marker::PhantomData;

// --- Traits ---

pub trait SigningKey {
    type Hasher: HashImpl;
    fn sign(&self, input: impl Writable) -> Result<Vec<u8>>;
    fn hash(&self, data: impl Writable) -> HashOutput {
        let mut hasher = <Self::Hasher as HashImpl>::hasher();
        data.write(&mut hasher);
        hasher.complete()
    }
    fn algorithm(&self) -> Algorithm;
}

pub trait HashContext: Writer + Sized {
    fn complete(self) -> HashOutput;
}

pub trait HashImpl {
    type Context: HashContext;
    fn hasher() -> Self::Context;
}

// --- Enums and Structs ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    RsaSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha256,
}

pub struct Sha256;

#[non_exhaustive]
pub enum HashOutput {
    RustCryptoSha256(sha2::digest::Output<sha2::Sha256>),
}

// --- Implementations ---

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::RustCryptoSha256(output) => output.as_ref(),
        }
    }
}

impl From<Algorithm> for HashAlgorithm {
    fn from(_: Algorithm) -> Self {
        HashAlgorithm::Sha256
    }
}

// --- RSA Key ---

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
    pub fn from_pkcs1_pem(private_key_pem: &str) -> Result<Self> {
        let inner = RsaPrivateKey::from_pkcs1_pem(private_key_pem)?;
        Ok(RsaKey {
            inner,
            padding: PhantomData,
        })
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let hash = self.hash(input);
        self.inner
            .sign(
                Pkcs1v15Sign::new::<<Self::Hasher as HashImpl>::Context>(),
                hash.as_ref(),
            )
            .map_err(|e| e.into())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

// --- SHA256 ---

impl Writer for sha2::Sha256 {
    fn write(&mut self, buf: &[u8]) {
        self.update(buf);
    }
}

impl HashImpl for Sha256 {
    type Context = sha2::Sha256;
    fn hasher() -> Self::Context {
        <Self::Context as Digest>::new()
    }
}

impl HashContext for sha2::Sha256 {
    fn complete(self) -> HashOutput {
        HashOutput::RustCryptoSha256(self.finalize())
    }
}
