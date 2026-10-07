use tempdir::TempDir;

fn scratch_file_exists() -> std::io::Result<bool> {
    let dir = TempDir::new("mendr")?;
    let path = dir.path().join("scratch.txt");
    std::fs::write(&path, "hello, mendr")?;
    Ok(path.exists())
}

fn main() -> std::io::Result<()> {
    println!("{}", scratch_file_exists()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn creates_files() {
        assert!(super::scratch_file_exists().unwrap());
    }
}
