use super::{Canonicalization, Signature};
use crate::common::headers::{HeaderStream, Writable, Writer};

pub struct CanonicalBody<'a> {
    canonicalization: Canonicalization,
    body: &'a [u8],
}

impl Writable for CanonicalBody<'_> {
    fn write(self, hasher: &mut impl Writer) {
        let mut crlf_seq = 0;
        match self.canonicalization {
            Canonicalization::Relaxed => {
                let mut last_ch = 0;
                let mut is_empty = true;
                for &ch in self.body {
                    match ch {
                        b' ' | b'\t' => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            is_empty = false;
                        }
                        b'\n' => crlf_seq += 1,
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            if last_ch == b' ' || last_ch == b'\t' {
                                hasher.write(b" ");
                            }
                            hasher.write(&[ch]);
                            is_empty = false;
                        }
                    }
                    last_ch = ch;
                }
                if !is_empty {
                    hasher.write(b"\r\n");
                }
            }
            Canonicalization::Simple => {
                for &ch in self.body {
                    match ch {
                        b'\n' => crlf_seq += 1,
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            hasher.write(&[ch]);
                        }
                    }
                }
                if crlf_seq == 0 && !self.body.is_empty() {
                    hasher.write(b"\r\n");
                }
            }
        }
    }
}

impl Canonicalization {
    pub fn canonicalize_headers<'a>(
        &self,
        headers: impl Iterator<Item = (&'a [u8], &'a [u8])>,
        hasher: &mut impl Writer,
    ) {
        match self {
            Canonicalization::Relaxed => {
                for (name, value) in headers {
                    for &ch in name {
                        if !ch.is_ascii_whitespace() {
                            hasher.write(&[ch.to_ascii_lowercase()]);
                        }
                    }
                    hasher.write(b":");
                    let mut bw = 0;
                    let mut last_ch = 0;
                    for &ch in value {
                        if !ch.is_ascii_whitespace() {
                            if [b' ', b'\t'].contains(&last_ch) && bw > 0 {
                                hasher.write_len(b" ", &mut bw);
                            }
                            hasher.write_len(&[ch], &mut bw);
                        }
                        last_ch = ch;
                    }
                    if last_ch == b'\n' {
                        hasher.write(b"\r\n");
                    }
                }
            }
            Canonicalization::Simple => {
                for (name, value) in headers {
                    hasher.write(name);
                    hasher.write(b":");
                    hasher.write(value);
                }
            }
        }
    }

    pub fn canonical_headers<'a>(&self, headers: Vec<(&'a [u8], &'a [u8])>) -> CanonicalHeaders<'a> {
        CanonicalHeaders { canonicalization: *self, headers }
    }

    pub fn canonical_body<'a>(&self, body: &'a [u8], l: u64) -> CanonicalBody<'a> {
        CanonicalBody {
            canonicalization: *self,
            body: if l == 0 || body.is_empty() { body } else { &body[..std::cmp::min(l as usize, body.len())] },
        }
    }

    pub fn serialize_name(&self, writer: &mut impl Writer) {
        writer.write(match self {
            Canonicalization::Relaxed => b"relaxed",
            Canonicalization::Simple => b"simple",
        });
    }
}

impl Signature {
    pub fn canonicalize<'x>(
        &self,
        mut message: impl HeaderStream<'x>,
    ) -> (usize, CanonicalHeaders<'x>, Vec<String>, CanonicalBody<'x>) {
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        while let Some((name, value)) = message.next_header() {
            if let Some(pos) = self.h.iter().position(|header| name.eq_ignore_ascii_case(header.as_bytes())) {
                headers.push((name, value));
                found_headers[pos] = true;
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let body = message.body();
        let body_len = body.len();
        let canonical_headers = self.ch.canonical_headers(headers);
        let canonical_body = self.ch.canonical_body(body, u64::MAX);

        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found { signed_headers.push(header.to_string()); }
        }

        (body_len, canonical_headers, signed_headers, canonical_body)
    }
}

pub struct CanonicalHeaders<'a> {
    canonicalization: Canonicalization,
    headers: Vec<(&'a [u8], &'a [u8])>,
}

impl Writable for CanonicalHeaders<'_> {
    fn write(self, writer: &mut impl Writer) {
        self.canonicalization.canonicalize_headers(self.headers.into_iter().rev(), writer)
    }
}
