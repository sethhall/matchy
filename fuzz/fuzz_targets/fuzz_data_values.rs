#![no_main]
use libfuzzer_sys::fuzz_target;
use matchy::{DatabaseBuilder, DataValue, MatchMode};
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    
    // Build various DataValue types from fuzzed input
    let mut builder = DatabaseBuilder::new(MatchMode::CaseSensitive);
    let mut data_map = HashMap::new();
    
    // Use different parts of input for different data types
    if data.len() >= 4 {
        // Try as integer
        let int_val = i32::from_le_bytes([
            data[0],
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);
        data_map.insert("int_field".to_string(), DataValue::Int(int_val));
    }
    
    if data.len() >= 8 {
        // Try as float
        let float_bytes = [
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ];
        let float_val = f64::from_le_bytes(float_bytes);
        // Only add if it's a valid float (not NaN or infinity)
        if float_val.is_finite() {
            data_map.insert("float_field".to_string(), DataValue::Float(float_val));
        }
    }
    
    // Try as string
    if let Ok(s) = std::str::from_utf8(data) {
        data_map.insert("string_field".to_string(), DataValue::String(s.to_string()));
        
        // Try as nested map
        let mut nested = HashMap::new();
        nested.insert("nested_str".to_string(), DataValue::String(s.to_string()));
        data_map.insert("map_field".to_string(), DataValue::Map(nested));
        
        // Try as array
        let arr = vec![
            DataValue::String(s.to_string()),
            DataValue::Int(42),
        ];
        data_map.insert("array_field".to_string(), DataValue::Array(arr));
    }
    
    // Add boolean based on first byte
    data_map.insert("bool_field".to_string(), DataValue::Bool(data[0] & 1 == 0));
    
    // Try to build database with complex data
    let _ = builder.add_entry("1.2.3.4", data_map.clone());
    let _ = builder.add_entry("*.example.com", data_map);
    
    // Try to build and query
    if let Ok(db_bytes) = builder.build() {
        if let Ok(db) = matchy::Database::from_bytes(db_bytes) {
            let _ = db.lookup("1.2.3.4");
            let _ = db.lookup("test.example.com");
        }
    }
});
