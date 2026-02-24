use std::fs;
use std::process;

fn usage() -> ! {
    eprintln!("pdfcrypt — lock or unlock PDF files\n");
    eprintln!("Usage:");
    eprintln!("  pdfcrypt lock   <input.pdf> <output.pdf> --user-password <pw> [--owner-password <pw>]");
    eprintln!("  pdfcrypt unlock <input.pdf> <output.pdf> --password <pw>\n");
    eprintln!("Options:");
    eprintln!("  --user-password   Password required to open the PDF (lock)");
    eprintln!("  --owner-password  Owner password for permissions (lock, defaults to user password)");
    eprintln!("  --password        Password to decrypt the PDF (unlock)");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "lock" => cmd_lock(&args[2..]),
        "unlock" => cmd_unlock(&args[2..]),
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("Unknown command: {other}");
            usage();
        }
    }
}

fn cmd_lock(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Error: lock requires <input> <output> and at least one password flag");
        usage();
    }

    let input = &args[0];
    let output = &args[1];
    let mut user_pw: Option<String> = None;
    let mut owner_pw: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--user-password" | "-u" => {
                i += 1;
                user_pw = Some(args.get(i).cloned().unwrap_or_default());
            }
            "--owner-password" | "-o" => {
                i += 1;
                owner_pw = Some(args.get(i).cloned().unwrap_or_default());
            }
            other => {
                eprintln!("Unknown option: {other}");
                usage();
            }
        }
        i += 1;
    }

    if user_pw.is_none() && owner_pw.is_none() {
        eprintln!("Error: at least --user-password or --owner-password is required");
        usage();
    }

    let user_pw = user_pw.unwrap_or_default();
    let owner_pw = owner_pw.unwrap_or_else(|| user_pw.clone());

    let data = fs::read(input).unwrap_or_else(|e| {
        eprintln!("Error reading {input}: {e}");
        process::exit(1);
    });

    let seed = format!("pdfcrypt-cli-{}-{}", input, data.len());

    match pdf_protect_unlock::lock_pdf_core(&data, &user_pw, &owner_pw, seed.as_bytes()) {
        Ok(result) => {
            fs::write(output, &result).unwrap_or_else(|e| {
                eprintln!("Error writing {output}: {e}");
                process::exit(1);
            });
            eprintln!("Locked: {input} -> {output}");
            eprintln!("  User password:  {user_pw}");
            if owner_pw != user_pw {
                eprintln!("  Owner password: {owner_pw}");
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_unlock(args: &[String]) {
    if args.len() < 4 {
        eprintln!("Error: unlock requires <input> <output> --password <pw>");
        usage();
    }

    let input = &args[0];
    let output = &args[1];
    let mut password = String::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--password" | "-p" => {
                i += 1;
                password = args.get(i).cloned().unwrap_or_default();
            }
            other => {
                eprintln!("Unknown option: {other}");
                usage();
            }
        }
        i += 1;
    }

    let data = fs::read(input).unwrap_or_else(|e| {
        eprintln!("Error reading {input}: {e}");
        process::exit(1);
    });

    match pdf_protect_unlock::unlock_pdf_core(&data, &password) {
        Ok(result) => {
            fs::write(output, &result).unwrap_or_else(|e| {
                eprintln!("Error writing {output}: {e}");
                process::exit(1);
            });
            eprintln!("Unlocked: {input} -> {output}");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
