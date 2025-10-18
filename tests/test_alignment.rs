use matchy::glob::MatchMode;
use matchy::paraglob_offset::Paraglob;
use matchy::serialization::{save, load};
use std::fs;
use std::mem;

#[test]
fn test_heap_allocation_alignment() {
    // Build a database in memory
    let patterns = vec!["*.txt", "test_*", "foo.bar"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    
    let buffer = pg.buffer();
    
    // Check that the AC buffer (which starts after the header) is 8-byte aligned
    let header_size = mem::size_of::<matchy::offset_format::ParaglobHeader>();
    let ac_buffer_start = header_size;
    
    // The buffer itself should be 8-byte aligned (Rust heap allocations)
    let buffer_addr = buffer.as_ptr() as usize;
    println!("Heap buffer address: 0x{:x}", buffer_addr);
    println!("Heap buffer alignment: {} bytes", buffer_addr % 8);
    assert_eq!(buffer_addr % 8, 0, "Heap allocated buffer must be 8-byte aligned");
    
    // AC section starts at offset 104 (header size)
    let ac_addr = unsafe { buffer.as_ptr().add(ac_buffer_start) } as usize;
    println!("AC section address in heap: 0x{:x}", ac_addr);
    println!("AC section alignment: {} bytes", ac_addr % 8);
    assert_eq!(ac_addr % 8, 0, "AC section in heap must be 8-byte aligned");
}

#[test]
fn test_mmap_alignment() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join("test_alignment.mxy");
    
    // Build and save a database
    let patterns = vec!["*.txt", "test_*", "foo.bar"];
    let pg = Paraglob::build_from_patterns(&patterns, MatchMode::CaseSensitive).unwrap();
    save(&pg, &db_path).unwrap();
    
    // Load via mmap
    let mmapped = load(&db_path, MatchMode::CaseSensitive).unwrap();
    let buffer = mmapped.paraglob().buffer();
    
    let header_size = mem::size_of::<matchy::offset_format::ParaglobHeader>();
    let ac_buffer_start = header_size;
    
    // Check mmap base address alignment
    let buffer_addr = buffer.as_ptr() as usize;
    println!("Mmap buffer address: 0x{:x}", buffer_addr);
    println!("Mmap buffer alignment: {} bytes", buffer_addr % 8);
    
    // mmap should give us page-aligned memory (at least 4KB = 4096 bytes)
    // Which is always 8-byte aligned since 4096 % 8 == 0
    assert_eq!(buffer_addr % 8, 0, "Mmap'd buffer must be at least 8-byte aligned");
    
    // AC section starts at file offset 104
    // If buffer base is 8-byte aligned and offset 104 is added (104 % 8 == 0),
    // then AC section should also be 8-byte aligned
    let ac_addr = unsafe { buffer.as_ptr().add(ac_buffer_start) } as usize;
    println!("AC section address in mmap: 0x{:x}", ac_addr);
    println!("AC section alignment: {} bytes", ac_addr % 8);
    assert_eq!(ac_addr % 8, 0, "AC section in mmap must be 8-byte aligned");
    
    // Cleanup
    fs::remove_file(&db_path).ok();
}

#[test]
fn test_embedded_data_alignment() {
    // Test that compile-time embedded data is properly aligned
    #[repr(align(8))]
    struct AlignedData([u8; 256]);
    
    static TEST_DATA: AlignedData = AlignedData([0u8; 256]);
    
    let addr = TEST_DATA.0.as_ptr() as usize;
    println!("Embedded data address: 0x{:x}", addr);
    println!("Embedded data alignment: {} bytes", addr % 8);
    assert_eq!(addr % 8, 0, "Embedded data with #[repr(align(8))] must be 8-byte aligned");
}
