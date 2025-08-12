use std::{
    iter::{Enumerate, Peekable},
    slice::Iter,
};

pub trait HeaderStream<'x> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])>;
    fn body(&mut self) -> &'x [u8];
}

pub(crate) struct HeaderIterator<'x> {
    message: &'x [u8],
    iter: Peekable<Enumerate<Iter<'x, u8>>>,
    start_pos: usize,
}

impl<'x> HeaderIterator<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            iter: message.iter().enumerate().peekable(),
            start_pos: 0,
        }
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        self.iter.peek().map(|(pos, _)| *pos)
    }
}

impl<'x> HeaderStream<'x> for HeaderIterator<'x> {
    fn next_header(&mut self) -> Option<(&'x [u8], &'x [u8])> {
        self.next()
    }

    fn body(&mut self) -> &'x [u8] {
        self.body_offset()
            .and_then(|offset| self.message.get(offset..))
            .unwrap_or_default()
    }
}

impl<'x> Iterator for HeaderIterator<'x> {
    type Item = (&'x [u8], &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut colon_pos = usize::MAX;
        let mut last_ch = 0;

        while let Some((pos, &ch)) = self.iter.next() {
            if colon_pos == usize::MAX {
                match ch {
                    b':' => {
                        colon_pos = pos;
                    }
                    b'\n' => {
                        if last_ch == b'\r' || self.start_pos == pos {
                            return None; // End of headers
                        } else if self
                            .iter
                            .peek()
                            .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                        {
                            let header_name = self
                                .message
                                .get(self.start_pos..pos + 1)
                                .unwrap_or_default();
                            self.start_pos = pos + 1;
                            return Some((header_name, b""));
                        }
                    }
                    _ => (),
                }
            } else if ch == b'\n'
                && self
                    .iter
                    .peek()
                    .is_none_or(|(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
            {
                let header_name = self
                    .message
                    .get(self.start_pos..colon_pos)
                    .unwrap_or_default();
                let header_value = self.message.get(colon_pos + 1..pos + 1).unwrap_or_default();
                self.start_pos = pos + 1;
                return Some((header_name, header_value));
            }
            last_ch = ch;
        }
        None
    }
}

// --- Writer Traits ---

pub trait HeaderWriter: Sized {
    fn write_header(&self, writer: &mut impl Writer);
    fn to_header(&self) -> String {
        let mut buf = Vec::new();
        self.write_header(&mut buf);
        String::from_utf8(buf).unwrap()
    }
}

pub trait Writable {
    fn write(self, writer: &mut impl Writer);
}

impl Writable for &[u8] {
    fn write(self, writer: &mut impl Writer) {
        writer.write(self);
    }
}

pub trait Writer {
    fn write(&mut self, buf: &[u8]);
    fn write_len(&mut self, buf: &[u8], len: &mut usize) {
        self.write(buf);
        *len += buf.len();
    }
}

impl Writer for Vec<u8> {
    fn write(&mut self, buf: &[u8]) {
        self.extend(buf);
    }
}
