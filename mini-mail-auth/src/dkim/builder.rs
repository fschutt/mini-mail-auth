use super::{Canonicalization, DkimSigner, Done, NeedDomain, NeedHeaders, NeedSelector};
use crate::common::crypto::SigningKey;

impl<T: SigningKey> DkimSigner<T> {
    pub fn from_key(key: T) -> DkimSigner<T, NeedDomain> {
        DkimSigner {
            _state: Default::default(),
            template: super::Signature {
                v: 1,
                a: key.algorithm(),
                ..Default::default()
            },
            key,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedDomain> {
    pub fn domain(mut self, domain: impl Into<String>) -> DkimSigner<T, NeedSelector> {
        self.template.d = domain.into();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedSelector> {
    pub fn selector(mut self, selector: impl Into<String>) -> DkimSigner<T, NeedHeaders> {
        self.template.s = selector.into();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, NeedHeaders> {
    pub fn headers(
        mut self,
        headers: impl IntoIterator<Item = impl Into<String>>,
    ) -> DkimSigner<T, Done> {
        self.template.h = headers.into_iter().map(|h| h.into()).collect();
        DkimSigner {
            _state: Default::default(),
            key: self.key,
            template: self.template,
        }
    }
}

impl<T: SigningKey> DkimSigner<T, Done> {
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.template.l = u64::from(body_length);
        self
    }

    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.template.ch = ch;
        self
    }

    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.template.cb = cb;
        self
    }
}
