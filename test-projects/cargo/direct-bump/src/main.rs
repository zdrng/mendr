use std::io::{Read, Seek, SeekFrom, Write};

fn roundtrip(text: &str) -> std::io::Result<String> {
    let mut file = tempfile::tempfile()?;
    file.write_all(text.as_bytes())?;
    file.seek(SeekFrom::Start(0))?;
    let mut out = String::new();
    file.read_to_string(&mut out)?;
    Ok(out)
}

fn main() -> std::io::Result<()> {
    println!("{}", roundtrip("hello, mendr")?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrips() {
        assert_eq!(super::roundtrip("hi").unwrap(), "hi");
    }
}
