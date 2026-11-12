use std::io::{self, BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: redactdsn [URL...]\nWith no arguments, reads lines from stdin and redacts every URL in them.");
        return;
    }
    if !args.is_empty() {
        for a in args {
            println!("{}", redactdsn::redact(&a));
        }
        return;
    }
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if writeln!(out, "{}", redactdsn::redact_text(&line)).is_err() {
            break;
        }
    }
}
