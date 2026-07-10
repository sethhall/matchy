use matchy_data_format::{DataDecoder, DataValue, MAX_POINTER_DEPTH, MAX_TOTAL_DEPTH};

fn push_short_pointer(buffer: &mut Vec<u8>, offset: usize) {
    assert!(offset < 2048);
    buffer.push(0x20 | u8::try_from((offset >> 8) & 0x7).unwrap());
    buffer.push(u8::try_from(offset & 0xff).unwrap());
}

fn pointer_chain(pointer_count: usize) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(pointer_count * 2 + 1);
    for index in 0..pointer_count {
        push_short_pointer(&mut buffer, (index + 1) * 2);
    }
    buffer.push(0x40); // Empty string
    buffer
}

fn push_array_header(buffer: &mut Vec<u8>, count: usize) {
    if count < 29 {
        buffer.push(u8::try_from(count).unwrap());
        buffer.push(0x04);
    } else if count < 285 {
        buffer.extend_from_slice(&[29, 0x04, u8::try_from(count - 29).unwrap()]);
    } else if count < 65_821 {
        buffer.extend_from_slice(&[30, 0x04]);
        buffer.extend_from_slice(&u16::try_from(count - 285).unwrap().to_be_bytes());
    } else {
        let adjusted = u32::try_from(count - 65_821).unwrap().to_be_bytes();
        buffer.extend_from_slice(&[31, 0x04, adjusted[1], adjusted[2], adjusted[3]]);
    }
}

#[test]
fn rejects_direct_pointer_cycle() {
    let buffer = [0x20, 0x00];
    let error = DataDecoder::new(&buffer, 0).decode(0).unwrap_err();
    assert_eq!(error, "Pointer cycle detected");
}

#[test]
fn rejects_pointer_cycle_through_container() {
    // Array containing a pointer back to the array itself.
    let buffer = [0x01, 0x04, 0x20, 0x00];
    let error = DataDecoder::new(&buffer, 0).decode(0).unwrap_err();
    assert_eq!(error, "Pointer cycle detected");
}

#[test]
fn bounds_structural_nesting() {
    let mut at_limit = Vec::new();
    for _ in 0..MAX_TOTAL_DEPTH {
        at_limit.extend_from_slice(&[0x01, 0x04]); // One-element array
    }
    at_limit.push(0x40); // Empty string at depth MAX_TOTAL_DEPTH
    assert!(DataDecoder::new(&at_limit, 0).decode(0).is_ok());

    let mut too_deep = Vec::new();
    for _ in 0..=MAX_TOTAL_DEPTH {
        too_deep.extend_from_slice(&[0x01, 0x04]);
    }
    too_deep.push(0x40);
    let error = DataDecoder::new(&too_deep, 0).decode(0).unwrap_err();
    assert_eq!(error, "Data nesting depth exceeded");
}

#[test]
fn bounds_pointer_depth() {
    let at_limit = pointer_chain(MAX_POINTER_DEPTH);
    assert_eq!(
        DataDecoder::new(&at_limit, 0).decode(0).unwrap(),
        DataValue::String(String::new())
    );

    let too_deep = pointer_chain(MAX_POINTER_DEPTH + 1);
    let error = DataDecoder::new(&too_deep, 0).decode(0).unwrap_err();
    assert_eq!(error, "Pointer depth exceeded");
}

#[test]
fn rejects_truncated_container_counts_before_reserving() {
    let maximum_array_count = [0x1f, 0x04, 0xff, 0xff, 0xff];
    let error = DataDecoder::new(&maximum_array_count, 0)
        .decode(0)
        .unwrap_err();
    assert_eq!(error, "Array element count exceeds remaining data");

    let maximum_map_count = [0xff, 0xff, 0xff, 0xff];
    let error = DataDecoder::new(&maximum_map_count, 0)
        .decode(0)
        .unwrap_err();
    assert_eq!(error, "Map entry count exceeds remaining data");
}

#[test]
fn rejects_truncated_payload_ranges() {
    let cases: &[&[u8]] = &[
        &[0x42, b'a'],             // Two-byte string, one byte present
        &[0x84, 1, 2, 3],          // Four-byte byte string, three present
        &[0xa2, 1],                // Two-byte uint16, one present
        &[0xc4, 1, 2, 3],          // Four-byte uint32, three present
        &[0x68, 0, 0, 0, 0, 0, 0], // Eight-byte double, six present
        &[0x38, 0, 0, 0],          // Four-byte pointer, three present
    ];

    for &buffer in cases {
        assert!(
            DataDecoder::new(buffer, 0).decode(0).is_err(),
            "truncated buffer was accepted: {buffer:?}"
        );
    }
}

#[test]
fn rejects_unknown_extended_type_without_panicking() {
    let buffer = [0x00, 249];
    let error = DataDecoder::new(&buffer, 0).decode(0).unwrap_err();
    assert_eq!(error, "Unknown extended type");
}

#[test]
fn enforces_fixed_width_and_boolean_sizes() {
    let invalid_double = [0x60, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        DataDecoder::new(&invalid_double, 0).decode(0),
        Err("Double must be 8 bytes")
    );

    assert_eq!(
        DataDecoder::new(&[0x00, 0x07], 0).decode(0),
        Ok(DataValue::Bool(false))
    );
    assert_eq!(
        DataDecoder::new(&[0x01, 0x07], 0).decode(0),
        Ok(DataValue::Bool(true))
    );
    assert_eq!(
        DataDecoder::new(&[0x02, 0x07], 0).decode(0),
        Err("Bool size must be 0 or 1")
    );
}

#[test]
fn short_int32_values_are_positive() {
    // MMDB specifies that signed integer fields shorter than four bytes are positive.
    let buffer = [0x01, 0x01, 0x80];
    assert_eq!(
        DataDecoder::new(&buffer, 0).decode(0),
        Ok(DataValue::Int32(128))
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "work-budget exhaustion fixture is prohibitively slow under Miri"
)]
fn bounds_acyclic_pointer_expansion() {
    let mut buffer = vec![0x40]; // Shared empty string at offset zero.
    let mut root_offset = 0;

    // Each layer is an array containing two pointers to the prior layer. The
    // serialized graph is tiny, but fully expanding it would grow exponentially.
    for _ in 0..20 {
        let previous = root_offset;
        root_offset = buffer.len();
        buffer.extend_from_slice(&[0x02, 0x04]);
        push_short_pointer(&mut buffer, previous);
        push_short_pointer(&mut buffer, previous);
    }

    let error = DataDecoder::new(&buffer, 0)
        .decode(u32::try_from(root_offset).unwrap())
        .unwrap_err();
    assert!(matches!(
        error,
        "Decoded value exceeds work limit" | "Decoded value exceeds allocation limit"
    ));
}

#[test]
fn preserves_moderate_pointer_sharing() {
    let mut buffer = Vec::new();
    push_array_header(&mut buffer, 100);
    buffer.extend(std::iter::repeat_n(0x40, 100));

    let root_offset = buffer.len();
    push_array_header(&mut buffer, 100);
    for _ in 0..100 {
        push_short_pointer(&mut buffer, 0);
    }

    let decoded = DataDecoder::new(&buffer, 0)
        .decode(u32::try_from(root_offset).unwrap())
        .unwrap();
    let DataValue::Array(items) = decoded else {
        panic!("expected root array");
    };
    assert_eq!(items.len(), 100);
    assert!(items
        .iter()
        .all(|item| matches!(item, DataValue::Array(shared) if shared.len() == 100)));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "shared decode-budget exhaustion fixture is prohibitively slow under Miri"
)]
fn shared_budget_bounds_aggregate_pointer_expansion() {
    // Each root expands 1,030 pointers through the same 30-pointer chain.
    // Either root fits the 64K minimum work budget on its own, while decoding
    // both as one logical query exceeds that shared budget.
    let mut buffer = pointer_chain(30);
    let first_root = buffer.len();
    push_array_header(&mut buffer, 1_030);
    for _ in 0..1_030 {
        push_short_pointer(&mut buffer, 0);
    }

    let second_root = buffer.len();
    push_array_header(&mut buffer, 1_030);
    for _ in 0..1_030 {
        push_short_pointer(&mut buffer, 0);
    }

    let decoder = DataDecoder::new(&buffer, 0);
    let first_root = u32::try_from(first_root).unwrap();
    let second_root = u32::try_from(second_root).unwrap();

    // The compatibility API still creates a fresh budget per decode.
    assert!(decoder.decode(first_root).is_ok());
    assert!(decoder.decode(second_root).is_ok());

    let mut budget = decoder.new_budget();
    assert!(decoder.decode_with_budget(first_root, &mut budget).is_ok());
    assert_eq!(
        decoder
            .decode_with_budget(second_root, &mut budget)
            .unwrap_err(),
        "Decoded value exceeds work limit"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "million-byte work-limit fixture is prohibitively slow under Miri"
)]
fn absolute_work_limit_precedes_large_container_reservation() {
    let count = 1_000_001;
    let mut buffer = Vec::with_capacity(count + 5);
    push_array_header(&mut buffer, count);
    buffer.extend(std::iter::repeat_n(0x40, count));

    let error = DataDecoder::new(&buffer, 0).decode(0).unwrap_err();
    assert_eq!(error, "Decoded value exceeds work limit");
}

#[test]
fn preserves_nonzero_base_offset_behavior() {
    let base_offset = 100;
    // Existing semantics treat both the requested offset and encoded pointer
    // as base-adjusted values. The pointer at relative zero targets relative two.
    let buffer = [0x20, 102, 0x40];
    assert_eq!(
        DataDecoder::new(&buffer, base_offset).decode(100),
        Ok(DataValue::String(String::new()))
    );
}
