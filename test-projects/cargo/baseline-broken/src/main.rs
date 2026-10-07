use smallstr::SmallString;

fn greeting(name: &str) -> SmallString<[u8; 16]> {
    let mut s = SmallString::from_str("hello, ");
    s.push_str(name);
    s
}

fn main() {
    println!("{}", greeting("mendr"));
}

#[cfg(test)]
mod tests {
    // Broken before mendr touches anything: the greeting has a comma.
    // mendr must not attempt fixes on a project whose tests already fail.
    #[test]
    fn greets() {
        assert_eq!(super::greeting("mendr").as_str(), "hello mendr");
    }
}
