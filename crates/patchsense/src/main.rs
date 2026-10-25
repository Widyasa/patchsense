fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("patchsense {version}");
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") || args.is_empty() {
        println!("patchsense {version}");
        println!("Prioritize vulnerabilities from lockfiles using OSV, EPSS, and CISA KEV.");
        return;
    }
    eprintln!("error: unknown arguments: {}", args.join(" "));
    std::process::exit(2);
}
