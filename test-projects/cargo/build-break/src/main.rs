/// `YYYY-MM-DD` of a UNIX timestamp (UTC), with time 0.1's `Tm` API.
/// time 0.2 removed `at_utc`/`Tm`/`strftime`, so the fix does not compile.
fn date(secs: i64) -> String {
    let tm = time::at_utc(time::Timespec::new(secs, 0));
    time::strftime("%Y-%m-%d", &tm).unwrap()
}

fn main() {
    println!("{}", date(time::get_time().sec));
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_dates() {
        assert_eq!(super::date(1_600_000_000), "2020-09-13");
    }
}
