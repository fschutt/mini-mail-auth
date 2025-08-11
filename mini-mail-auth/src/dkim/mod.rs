pub mod builder;
pub mod canonicalize;
pub mod headers;
pub mod sign;

use crate::common::crypto::{Algorithm, SigningKey};
use std::marker::PhantomData;

// --- Enums and Structs ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Canonicalization {
    #[default]
    Relaxed,
    Simple,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    pub v: u32,
    pub a: Algorithm,
    pub d: String,
    pub s: String,
    pub b: Vec<u8>,
    pub bh: Vec<u8>,
    pub h: Vec<String>,
    pub l: u64,
    pub t: u64,
    pub ch: Canonicalization,
    pub cb: Canonicalization,
}

// --- Builder Pattern ---

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DkimSigner<T: SigningKey, State = NeedDomain> {
    pub(crate) _state: PhantomData<State>,
    pub(crate) key: T,
    pub(crate) template: Signature,
}

pub struct NeedDomain;
pub struct NeedSelector;
pub struct NeedHeaders;
pub struct Done;
