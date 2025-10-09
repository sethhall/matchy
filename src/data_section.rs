//! Data section encoding and decoding for Paraglob v2
//!
//! Provides full MMDB-compatible data encoding for storing pattern-associated data.
//! Implements the complete MaxMind DB data type specification.
//!
//! # Supported Types
//!
//! Complete MMDB type support:
//! - **Pointer**: Reference to another data item (with base handling)
//! - **String**: UTF-8 text data
//! - **Double**: 64-bit floating point (IEEE 754)
//! - **Bytes**: Raw byte arrays
//! - **Uint16**: Unsigned 16-bit integers
//! - **Uint32**: Unsigned 32-bit integers
//! - **Map**: Key-value pairs (string keys)
//! - **Int32**: Signed 32-bit integers
//! - **Uint64**: Unsigned 64-bit integers
//! - **Uint128**: Unsigned 128-bit integers
//! - **Array**: Ordered lists of values
//! - **Bool**: Boolean values
//! - **Float**: 32-bit floating point (IEEE 754)
//!
//! # Format
//!
//! Uses MMDB encoding: control byte(s) followed by data.
//! Control byte encodes type (3 bits) and size/payload (5 bits).
//!
//! See: https://maxmind.github.io/MaxMind-DB/

use std::collections::HashMap;

/// Data value that can be stored in the data section
///
/// This enum represents all MMDB data types and can be used
/// for both standalone .pgb files and MMDB-embedded data.
#[derive(Debug, Clone, PartialEq)]
pub enum DataValue {
    /// Pointer to another data item (offset)
    Pointer(u32),
    /// UTF-8 string
    String(String),
    /// IEEE 754 double precision float
    Double(f64),
    /// Raw byte array
    Bytes(Vec<u8>),
    /// Unsigned 16-bit integer
    Uint16(u16),
    /// Unsigned 32-bit integer
    Uint32(u32),
    /// Key-value map (string keys only per MMDB spec)
    Map(HashMap<String, DataValue>),
    /// Signed 32-bit integer
    Int32(i32),
    /// Unsigned 64-bit integer
    Uint64(u64),
    /// Unsigned 128-bit integer
    Uint128(u128),
    /// Array of values
    Array(Vec<DataValue>),
    /// Boolean value
    Bool(bool),
    /// IEEE 754 single precision float
    Float(f32),
}

/// Data section encoder
///
/// Builds a data section by encoding values and tracking offsets.
/// Supports deduplication - identical values get the same offset.
pub struct DataEncoder {
    /// Encoded data buffer
    buffer: Vec<u8>,
    /// Map from serialized value to offset (for deduplication)
    dedup_map: HashMap<Vec<u8>, u32>,
}

impl DataEncoder {
    /// Create a new encoder
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            dedup_map: HashMap::new(),
        }
    }

    /// Encode a value and return its offset
    ///
    /// If the value was previously encoded, returns the existing offset.
    /// This enables automatic deduplication.
    pub fn encode(&mut self, value: &DataValue) -> u32 {
        // First, serialize to temp buffer to check if we've seen this before
        let mut temp = Vec::new();
        Self::encode_to_buffer(value, &mut temp);

        // Check deduplication map
        if let Some(&offset) = self.dedup_map.get(&temp) {
            return offset;
        }

        // New value - add to main buffer
        let offset = self.buffer.len() as u32;
        self.buffer.extend_from_slice(&temp);
        self.dedup_map.insert(temp, offset);
        offset
    }

    /// Get the final encoded data section
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// Get current buffer size
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    /// Encode a value to a buffer
    fn encode_to_buffer(value: &DataValue, buffer: &mut Vec<u8>) {
        match value {
            DataValue::Pointer(offset) => Self::encode_pointer(*offset, buffer),
            DataValue::String(s) => Self::encode_string(s, buffer),
            DataValue::Double(d) => Self::encode_double(*d, buffer),
            DataValue::Bytes(b) => Self::encode_bytes(b, buffer),
            DataValue::Uint16(n) => Self::encode_uint16(*n, buffer),
            DataValue::Uint32(n) => Self::encode_uint32(*n, buffer),
            DataValue::Map(m) => Self::encode_map(m, buffer),
            DataValue::Int32(n) => Self::encode_int32(*n, buffer),
            DataValue::Uint64(n) => Self::encode_uint64(*n, buffer),
            DataValue::Uint128(n) => Self::encode_uint128(*n, buffer),
            DataValue::Array(a) => Self::encode_array(a, buffer),
            DataValue::Bool(b) => Self::encode_bool(*b, buffer),
            DataValue::Float(f) => Self::encode_float(*f, buffer),
        }
    }

    // Type 1: Pointer
    fn encode_pointer(offset: u32, buffer: &mut Vec<u8>) {
        let size = if offset < 0x800 {
            0 // 11 bits
        } else if offset < 0x80800 {
            1 // 19 bits
        } else if offset < 0x8080800 {
            2 // 27 bits
        } else {
            3 // 32 bits
        };

        let ctrl = 0x20 | (size << 3); // Type 1 << 5, size in bits 3-4
        buffer.push(ctrl);

        match size {
            0 => {
                // 11 bits: next 11 bits contain offset
                let b0 = ((offset >> 8) & 0x7) as u8;
                let b1 = (offset & 0xFF) as u8;
                buffer.push(b0);
                buffer.push(b1);
            }
            1 => {
                // 19 bits: next 19 bits contain offset + 2048
                let adjusted = offset - 0x800;
                let b0 = ((adjusted >> 16) & 0x7) as u8;
                let b1 = ((adjusted >> 8) & 0xFF) as u8;
                let b2 = (adjusted & 0xFF) as u8;
                buffer.push(b0);
                buffer.push(b1);
                buffer.push(b2);
            }
            2 => {
                // 27 bits: next 27 bits contain offset + 526336
                let adjusted = offset - 0x80800;
                let b0 = ((adjusted >> 24) & 0x7) as u8;
                let b1 = ((adjusted >> 16) & 0xFF) as u8;
                let b2 = ((adjusted >> 8) & 0xFF) as u8;
                let b3 = (adjusted & 0xFF) as u8;
                buffer.push(b0);
                buffer.push(b1);
                buffer.push(b2);
                buffer.push(b3);
            }
            _ => {
                // 32 bits: next 32 bits contain offset
                buffer.extend_from_slice(&offset.to_be_bytes());
            }
        }
    }

    // Type 2: String (UTF-8)
    fn encode_string(s: &str, buffer: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        Self::encode_with_size(2, bytes.len(), buffer);
        buffer.extend_from_slice(bytes);
    }

    // Type 3: Double (IEEE 754, 64-bit)
    fn encode_double(d: f64, buffer: &mut Vec<u8>) {
        buffer.push(0x68); // Type 3 << 5, size 8
        buffer.extend_from_slice(&d.to_be_bytes());
    }

    // Type 4: Bytes (raw binary)
    fn encode_bytes(b: &[u8], buffer: &mut Vec<u8>) {
        Self::encode_with_size(4, b.len(), buffer);
        buffer.extend_from_slice(b);
    }

    // Type 5: Uint16
    fn encode_uint16(n: u16, buffer: &mut Vec<u8>) {
        buffer.push(0xA2); // Type 5 << 5, size 2
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 6: Uint32
    fn encode_uint32(n: u32, buffer: &mut Vec<u8>) {
        buffer.push(0xC4); // Type 6 << 5, size 4
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 7: Map
    fn encode_map(m: &HashMap<String, DataValue>, buffer: &mut Vec<u8>) {
        Self::encode_with_size(7, m.len(), buffer);

        // Encode key-value pairs (sorted by key for deterministic output)
        let mut pairs: Vec<_> = m.iter().collect();
        pairs.sort_by_key(|(k, _)| *k);

        for (key, value) in pairs {
            Self::encode_string(key, buffer);
            Self::encode_to_buffer(value, buffer);
        }
    }

    // Extended types (type 0)
    
    // Type 8: Int32 (extended type 1)
    fn encode_int32(n: i32, buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        buffer.push(0x24); // (8-7)=1, 1<<5=0x20, size=4, 0x20|0x04=0x24
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 9: Uint64 (extended type 2)
    fn encode_uint64(n: u64, buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        buffer.push(0x48); // (9-7)=2, 2<<5=0x40, size=8, 0x40|0x08=0x48
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 10: Uint128 (extended type 3)
    fn encode_uint128(n: u128, buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        buffer.push(0x70); // (10-7)=3, 3<<5=0x60, size=16, 0x60|0x10=0x70
        buffer.extend_from_slice(&n.to_be_bytes());
    }

    // Type 11: Array
    fn encode_array(a: &[DataValue], buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        Self::encode_with_size_extended(11, a.len(), buffer);
        
        for value in a {
            Self::encode_to_buffer(value, buffer);
        }
    }

    // Type 14: Bool (extended type 7)
    fn encode_bool(b: bool, buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        if b {
            buffer.push(0xE1); // (14-7)=7, 7<<5=0xE0, size=1, 0xE0|0x01=0xE1
        } else {
            buffer.push(0xE0); // (14-7)=7, 7<<5=0xE0, size=0, 0xE0|0x00=0xE0
        }
    }

    // Type 15: Float (IEEE 754, 32-bit) (extended type 8)
    fn encode_float(f: f32, buffer: &mut Vec<u8>) {
        buffer.push(0x00); // Extended type marker
        buffer.push(0x04); // (15-7)=8, (8%8)<<5=0x00, size=4, 0x00|0x04=0x04
        buffer.extend_from_slice(&f.to_be_bytes());
    }

    /// Encode control byte with size for standard types
    fn encode_with_size(type_id: u8, size: usize, buffer: &mut Vec<u8>) {
        let type_bits = type_id << 5;
        
        if size < 29 {
            buffer.push(type_bits | (size as u8));
        } else if size < 29 + 256 {
            buffer.push(type_bits | 29);
            buffer.push((size - 29) as u8);
        } else if size < 29 + 256 + 65536 {
            buffer.push(type_bits | 30);
            let adjusted = size - 29 - 256;
            buffer.extend_from_slice(&(adjusted as u16).to_be_bytes());
        } else {
            buffer.push(type_bits | 31);
            let adjusted = size - 29 - 256 - 65536;
            buffer.extend_from_slice(&(adjusted as u32).to_be_bytes()[1..]); // 3 bytes
        }
    }

    /// Encode size for extended types (after 0x00 marker)
    fn encode_with_size_extended(type_id: u8, size: usize, buffer: &mut Vec<u8>) {
        let type_bits = (type_id - 7) << 5; // Extended types start at 7
        
        if size < 29 {
            buffer.push(type_bits | (size as u8));
        } else if size < 29 + 256 {
            buffer.push(type_bits | 29);
            buffer.push((size - 29) as u8);
        } else if size < 29 + 256 + 65536 {
            buffer.push(type_bits | 30);
            let adjusted = size - 29 - 256;
            buffer.extend_from_slice(&(adjusted as u16).to_be_bytes());
        } else {
            buffer.push(type_bits | 31);
            let adjusted = size - 29 - 256 - 65536;
            buffer.extend_from_slice(&(adjusted as u32).to_be_bytes()[1..]); // 3 bytes
        }
    }
}

impl Default for DataEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Data section decoder
///
/// Decodes values from an encoded data section buffer.
/// Fully compatible with MMDB format.
pub struct DataDecoder<'a> {
    buffer: &'a [u8],
    base_offset: usize,
}

impl<'a> DataDecoder<'a> {
    /// Create a decoder for a data section
    ///
    /// # Arguments
    /// * `buffer` - The encoded data buffer
    /// * `base_offset` - Base offset for pointer calculations (0 for standalone data)
    pub fn new(buffer: &'a [u8], base_offset: usize) -> Self {
        Self {
            buffer,
            base_offset,
        }
    }

    /// Decode a value at the given offset
    pub fn decode(&self, offset: u32) -> Result<DataValue, &'static str> {
        let mut cursor = offset as usize;
        if cursor < self.base_offset {
            return Err("Offset before base");
        }
        cursor -= self.base_offset;
        self.decode_at(&mut cursor)
    }

    fn decode_at(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor >= self.buffer.len() {
            return Err("Cursor out of bounds");
        }

        let ctrl = self.buffer[*cursor];
        *cursor += 1;

        let type_id = ctrl >> 5;
        let payload = ctrl & 0x1F;

        match type_id {
            0 => self.decode_extended(cursor, payload),
            1 => self.decode_pointer(cursor, payload),
            2 => self.decode_string(cursor, payload),
            3 => self.decode_double(cursor),
            4 => self.decode_bytes(cursor, payload),
            5 => self.decode_uint16(cursor),
            6 => self.decode_uint32(cursor),
            7 => self.decode_map(cursor, payload),
            _ => Err("Invalid type"),
        }
    }

    fn decode_extended(&self, cursor: &mut usize, _payload: u8) -> Result<DataValue, &'static str> {
        if *cursor >= self.buffer.len() {
            return Err("Extended type truncated");
        }

        let ext_byte = self.buffer[*cursor];
        *cursor += 1;

        let ext_type = (ext_byte >> 5) + 7;  // Add 7 to get actual type
        let ext_size = ext_byte & 0x1F;

        // Handle wrap-around for types >= 15
        let actual_type = if ext_type <= 14 {
            ext_type
        } else {
            // Type 15: ext_type will be 15 when (ext_byte>>5)+7 = 15
            // That means ext_byte>>5 = 8, but 8%8=0, so ext_byte>>5 will be 0
            // So when we see ext_byte>>5 = 0 and we're in extended, it could be type 15
            // We need to check the size field to differentiate
            if ext_type == 7 && ext_size == 4 {
                15  // Float has size 4
            } else {
                ext_type
            }
        };

        match actual_type {
            7 => {
                // Could be extended type 0 (shouldn't happen) or wrapping
                // Check size to determine
                if ext_size == 4 {
                    // This is actually type 15 (Float) wrapping around
                    self.decode_float(cursor)
                } else {
                    Err("Invalid extended type 0")
                }
            }
            8 => self.decode_int32(cursor),       // Extended type 1
            9 => self.decode_uint64(cursor),      // Extended type 2
            10 => self.decode_uint128(cursor),    // Extended type 3
            11 => self.decode_array(cursor, ext_size),  // Extended type 4
            14 => Ok(DataValue::Bool(ext_size != 0)),   // Extended type 7
            15 => self.decode_float(cursor),      // Extended type 8
            _ => Err("Unknown extended type"),
        }
    }

    fn decode_pointer(&self, cursor: &mut usize, payload: u8) -> Result<DataValue, &'static str> {
        let size_bits = (payload >> 3) & 0x3;  // Extract bits 3-4
        let offset = match size_bits {
            0 => {
                // 11 bits
                if *cursor + 1 > self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let b0 = self.buffer[*cursor] as u32;
                let b1 = self.buffer[*cursor + 1] as u32;
                *cursor += 2;
                ((b0 & 0x7) << 8) | b1
            }
            1 => {
                // 19 bits
                if *cursor + 2 > self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let b0 = self.buffer[*cursor] as u32;
                let b1 = self.buffer[*cursor + 1] as u32;
                let b2 = self.buffer[*cursor + 2] as u32;
                *cursor += 3;
                0x800 + (((b0 & 0x7) << 16) | (b1 << 8) | b2)
            }
            2 => {
                // 27 bits
                if *cursor + 3 > self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let b0 = self.buffer[*cursor] as u32;
                let b1 = self.buffer[*cursor + 1] as u32;
                let b2 = self.buffer[*cursor + 2] as u32;
                let b3 = self.buffer[*cursor + 3] as u32;
                *cursor += 4;
                0x80800 + (((b0 & 0x7) << 24) | (b1 << 16) | (b2 << 8) | b3)
            }
            3 => {
                // 32 bits
                if *cursor + 4 > self.buffer.len() {
                    return Err("Pointer data truncated");
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
                *cursor += 4;
                u32::from_be_bytes(bytes)
            }
            _ => return Err("Invalid pointer size"),
        };

        Ok(DataValue::Pointer(offset))
    }

    fn decode_string(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let len = self.decode_size(cursor, size_bits)?;

        if *cursor + len > self.buffer.len() {
            return Err("String data out of bounds");
        }

        let s = std::str::from_utf8(&self.buffer[*cursor..*cursor + len])
            .map_err(|_| "Invalid UTF-8")?;
        *cursor += len;

        Ok(DataValue::String(s.to_string()))
    }

    fn decode_double(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 8 > self.buffer.len() {
            return Err("Double data out of bounds");
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 8]);
        *cursor += 8;

        Ok(DataValue::Double(f64::from_be_bytes(bytes)))
    }

    fn decode_bytes(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let len = self.decode_size(cursor, size_bits)?;

        if *cursor + len > self.buffer.len() {
            return Err("Bytes data out of bounds");
        }

        let bytes = self.buffer[*cursor..*cursor + len].to_vec();
        *cursor += len;

        Ok(DataValue::Bytes(bytes))
    }

    fn decode_uint16(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 2 > self.buffer.len() {
            return Err("Uint16 data out of bounds");
        }

        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 2]);
        *cursor += 2;

        Ok(DataValue::Uint16(u16::from_be_bytes(bytes)))
    }

    fn decode_uint32(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 4 > self.buffer.len() {
            return Err("Uint32 data out of bounds");
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
        *cursor += 4;

        Ok(DataValue::Uint32(u32::from_be_bytes(bytes)))
    }

    fn decode_map(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let count = self.decode_size(cursor, size_bits)?;
        let mut map = HashMap::new();

        for _ in 0..count {
            let key = match self.decode_at(cursor)? {
                DataValue::String(s) => s,
                _ => return Err("Map key must be string"),
            };

            let value = self.decode_at(cursor)?;
            map.insert(key, value);
        }

        Ok(DataValue::Map(map))
    }

    fn decode_int32(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 4 > self.buffer.len() {
            return Err("Int32 data out of bounds");
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
        *cursor += 4;

        Ok(DataValue::Int32(i32::from_be_bytes(bytes)))
    }

    fn decode_uint64(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 8 > self.buffer.len() {
            return Err("Uint64 data out of bounds");
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 8]);
        *cursor += 8;

        Ok(DataValue::Uint64(u64::from_be_bytes(bytes)))
    }

    fn decode_uint128(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 16 > self.buffer.len() {
            return Err("Uint128 data out of bounds");
        }

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 16]);
        *cursor += 16;

        Ok(DataValue::Uint128(u128::from_be_bytes(bytes)))
    }

    fn decode_array(&self, cursor: &mut usize, size_bits: u8) -> Result<DataValue, &'static str> {
        let count = self.decode_size(cursor, size_bits)?;
        let mut array = Vec::with_capacity(count);

        for _ in 0..count {
            array.push(self.decode_at(cursor)?);
        }

        Ok(DataValue::Array(array))
    }

    fn decode_float(&self, cursor: &mut usize) -> Result<DataValue, &'static str> {
        if *cursor + 4 > self.buffer.len() {
            return Err("Float data out of bounds");
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 4]);
        *cursor += 4;

        Ok(DataValue::Float(f32::from_be_bytes(bytes)))
    }

    fn decode_size(&self, cursor: &mut usize, size_bits: u8) -> Result<usize, &'static str> {
        match size_bits {
            0..=28 => Ok(size_bits as usize),
            29 => {
                if *cursor >= self.buffer.len() {
                    return Err("Size byte out of bounds");
                }
                let size = self.buffer[*cursor] as usize;
                *cursor += 1;
                Ok(29 + size)
            }
            30 => {
                if *cursor + 2 > self.buffer.len() {
                    return Err("Size bytes out of bounds");
                }
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&self.buffer[*cursor..*cursor + 2]);
                *cursor += 2;
                Ok(29 + 256 + u16::from_be_bytes(bytes) as usize)
            }
            31 => {
                if *cursor + 3 > self.buffer.len() {
                    return Err("Size bytes out of bounds");
                }
                let b0 = self.buffer[*cursor] as usize;
                let b1 = self.buffer[*cursor + 1] as usize;
                let b2 = self.buffer[*cursor + 2] as usize;
                *cursor += 3;
                Ok(29 + 256 + 65536 + ((b0 << 16) | (b1 << 8) | b2))
            }
            _ => Err("Invalid size encoding"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_all_types() {
        let mut encoder = DataEncoder::new();

        // Test each type
        let string_val = DataValue::String("hello".to_string());
        let uint16_val = DataValue::Uint16(12345);
        let uint32_val = DataValue::Uint32(0xDEADBEEF);
        let uint64_val = DataValue::Uint64(0x123456789ABCDEF0);
        let uint128_val = DataValue::Uint128(0x0123456789ABCDEF0123456789ABCDEF);
        let int32_val = DataValue::Int32(-42);
        let double_val = DataValue::Double(3.14159265359);
        let float_val = DataValue::Float(2.71828);
        let bool_val = DataValue::Bool(true);
        let bytes_val = DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let offsets = vec![
            encoder.encode(&string_val),
            encoder.encode(&uint16_val),
            encoder.encode(&uint32_val),
            encoder.encode(&uint64_val),
            encoder.encode(&uint128_val),
            encoder.encode(&int32_val),
            encoder.encode(&double_val),
            encoder.encode(&float_val),
            encoder.encode(&bool_val),
            encoder.encode(&bytes_val),
        ];

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        let values = vec![
            string_val, uint16_val, uint32_val, uint64_val, uint128_val,
            int32_val, double_val, float_val, bool_val, bytes_val,
        ];

        for (offset, expected) in offsets.iter().zip(values.iter()) {
            let decoded = decoder.decode(*offset).unwrap();
            assert_eq!(&decoded, expected);
        }
    }

    #[test]
    fn test_encode_decode_map() {
        let mut encoder = DataEncoder::new();
        let mut map = HashMap::new();
        map.insert("country".to_string(), DataValue::String("US".to_string()));
        map.insert("asn".to_string(), DataValue::Uint32(13335));
        map.insert("score".to_string(), DataValue::Double(0.95));

        let value = DataValue::Map(map.clone());
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_encode_decode_array() {
        let mut encoder = DataEncoder::new();
        let value = DataValue::Array(vec![
            DataValue::String("tag1".to_string()),
            DataValue::String("tag2".to_string()),
            DataValue::Uint32(123),
            DataValue::Bool(false),
        ]);
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_deduplication() {
        let mut encoder = DataEncoder::new();

        // Encode same value multiple times
        let value = DataValue::String("test".to_string());
        let offset1 = encoder.encode(&value);
        let offset2 = encoder.encode(&value);
        let offset3 = encoder.encode(&value);

        // Should get same offset (deduplicated)
        assert_eq!(offset1, offset2);
        assert_eq!(offset2, offset3);

        // Different value gets different offset
        let value2 = DataValue::String("different".to_string());
        let offset4 = encoder.encode(&value2);
        assert_ne!(offset1, offset4);
    }

    #[test]
    fn test_complex_nested_structure() {
        let mut encoder = DataEncoder::new();

        // Build threat intelligence data structure
        let mut threat_data = HashMap::new();
        threat_data.insert("threat_level".to_string(), DataValue::String("high".to_string()));
        threat_data.insert("category".to_string(), DataValue::String("malware".to_string()));
        threat_data.insert("confidence".to_string(), DataValue::Float(0.98));
        threat_data.insert("first_seen".to_string(), DataValue::Uint64(1704067200));
        
        let mut indicators = HashMap::new();
        indicators.insert("ip_count".to_string(), DataValue::Uint32(42));
        indicators.insert("domain_count".to_string(), DataValue::Uint32(15));
        
        threat_data.insert("indicators".to_string(), DataValue::Map(indicators));
        threat_data.insert(
            "tags".to_string(),
            DataValue::Array(vec![
                DataValue::String("botnet".to_string()),
                DataValue::String("c2".to_string()),
            ]),
        );
        threat_data.insert("active".to_string(), DataValue::Bool(true));

        let value = DataValue::Map(threat_data);
        let offset = encoder.encode(&value);

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);
        let decoded = decoder.decode(offset).unwrap();

        assert_eq!(decoded, value);
    }

    #[test]
    fn test_large_strings() {
        let mut encoder = DataEncoder::new();
        
        // Test string size encodings
        let short = "x".repeat(28);  // < 29
        let medium = "x".repeat(100); // 29..285
        let long = "x".repeat(1000);  // > 285

        let offset1 = encoder.encode(&DataValue::String(short.clone()));
        let offset2 = encoder.encode(&DataValue::String(medium.clone()));
        let offset3 = encoder.encode(&DataValue::String(long.clone()));

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        assert_eq!(decoder.decode(offset1).unwrap(), DataValue::String(short));
        assert_eq!(decoder.decode(offset2).unwrap(), DataValue::String(medium));
        assert_eq!(decoder.decode(offset3).unwrap(), DataValue::String(long));
    }

    #[test]
    fn test_pointer_encoding() {
        let mut encoder = DataEncoder::new();
        
        // Test different pointer sizes
        let ptrs = vec![
            DataValue::Pointer(0x100),        // 11-bit
            DataValue::Pointer(0x10000),      // 19-bit
            DataValue::Pointer(0x1000000),    // 27-bit
            DataValue::Pointer(0xDEADBEEF),   // 32-bit
        ];

        let offsets: Vec<_> = ptrs.iter().map(|p| encoder.encode(p)).collect();

        let bytes = encoder.into_bytes();
        let decoder = DataDecoder::new(&bytes, 0);

        for (offset, expected) in offsets.iter().zip(ptrs.iter()) {
            let decoded = decoder.decode(*offset).unwrap();
            assert_eq!(&decoded, expected);
        }
    }
}
