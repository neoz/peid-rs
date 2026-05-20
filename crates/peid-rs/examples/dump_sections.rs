fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_sections <file>");
    let bytes = std::fs::read(&path).expect("read");
    match goblin::Object::parse(&bytes) {
        Ok(goblin::Object::PE(pe)) => {
            println!("PE: {} sections", pe.sections.len());
            for s in &pe.sections {
                let name = s.name().unwrap_or("<bad>");
                let raw = std::str::from_utf8(&s.name)
                    .map(|s| s.trim_end_matches('\0').to_string())
                    .unwrap_or_else(|_| format!("{:02x?}", s.name));
                println!("  {:?} (raw bytes: {:?})  va=0x{:x}  vsize=0x{:x}", name, raw, s.virtual_address, s.virtual_size);
            }
        }
        _ => println!("not a PE"),
    }
}
