use super::{canonicalize::CanonicalHeaders, DkimSigner, Done, Signature};
use crate::{
    common::{
        crypto::SigningKey,
        headers::{HeaderIterator, HeaderStream, Writable, Writer},
    },
    Error,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use std::time::SystemTime;

impl<T: SigningKey> DkimSigner<T, Done> {
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        self.sign_stream(
            HeaderIterator::new(message),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    fn sign_stream<'x>(
        &self,
        message: impl HeaderStream<'x>,
        now: u64,
    ) -> crate::Result<Signature> {
        let (body_len, canonical_headers, signed_headers, canonical_body) =
            self.template.canonicalize(message);

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        let mut signature = self.template.clone();
        let body_hash = self.key.hash(canonical_body);
        signature.bh = BASE64_STANDARD.encode(body_hash.as_ref()).into_bytes();
        signature.t = now;
        signature.h = signed_headers;
        if signature.l > 0 {
            signature.l = body_len as u64;
        }

        let b = self.key.sign(SignableMessage {
            headers: canonical_headers,
            signature: &signature,
        })?;

        signature.b = BASE64_STANDARD.encode(&b).into_bytes();

        Ok(signature)
    }
}

pub(super) struct SignableMessage<'a> {
    headers: CanonicalHeaders<'a>,
    signature: &'a Signature,
}

impl Writable for SignableMessage<'_> {
    fn write(self, writer: &mut impl Writer) {
        self.headers.write(writer);
        self.signature.write(writer, false);
    }
}
