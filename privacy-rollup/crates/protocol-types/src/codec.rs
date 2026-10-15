use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEnd,
    TrailingBytes,
    NonCanonicalField,
    NonCanonicalBool,
    NonMinimalCompactSize,
    AmountOutOfRange,
    LengthOutOfRange,
    UnknownTag,
    BadMagic,
    BadOrder,
}

pub struct Writer(pub Vec<u8>);

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn compact_size(&mut self, v: u64) -> &mut Self {
        match v {
            0..=252 => self.u8(v as u8),
            253..=0xffff => self.u8(253).bytes(&(v as u16).to_le_bytes()),
            0x1_0000..=0xffff_ffff => self.u8(254).u32(v as u32),
            _ => self.u8(255).u64(v),
        }
    }
    pub fn var_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.compact_size(v.len() as u64).bytes(v)
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEnd);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::NonCanonicalBool),
        }
    }
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn amount(&mut self) -> Result<u64, DecodeError> {
        let v = self.u64()?;
        if v > crate::MAX_MONEY {
            return Err(DecodeError::AmountOutOfRange);
        }
        Ok(v)
    }
    /// Bitcoin CompactSize, rejecting non-minimal encodings.
    pub fn compact_size(&mut self) -> Result<u64, DecodeError> {
        let (v, min) = match self.u8()? {
            253 => (self.u16()? as u64, 253),
            254 => (self.u32()? as u64, 0x1_0000),
            255 => (self.u64()?, 0x1_0000_0000),
            b => return Ok(b as u64),
        };
        if v < min {
            return Err(DecodeError::NonMinimalCompactSize);
        }
        Ok(v)
    }
    pub fn var_bytes(&mut self, max: usize) -> Result<&'a [u8], DecodeError> {
        let n = self.compact_size()?;
        if n > max as u64 {
            return Err(DecodeError::LengthOutOfRange);
        }
        self.take(n as usize)
    }
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos != self.buf.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(())
    }
}

/// Types with a single canonical byte encoding.
pub trait Canonical: Sized {
    fn encode_to(&self, w: &mut Writer);
    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_to(&mut w);
        w.finish()
    }
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode_from(&mut r)?;
        r.finish()?;
        Ok(v)
    }
}
