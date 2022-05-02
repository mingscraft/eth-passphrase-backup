use clap::{Arg, Command};
use colored::Colorize;
use eth_passphrase_backup::restore_from_share;
use eth_passphrase_backup::{get_share, Passphrase};
use std::process;

fn main() {
    let matches = Command::new("sss")
        .about("Ethereum HD wallet passphase backup utilities")
        .version("0.1.0")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .author("codeandplay")
        .subcommand(
            Command::new("backup")
                .short_flag('b')
                .long_flag("backup")
                .about("Create backup shares from HD wallet passphrase")
                .arg(
                    Arg::new("passphrase")
                        .short('p')
                        .long("passphrase")
                        .help("Passphrase to generate share from.")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("restore")
                .short_flag('r')
                .long_flag("restore")
                .about("Restore HD wallet passphrase from shares")
                .arg(
                    Arg::new("share")
                        .short('s')
                        .long("share")
                        .help("Backup share that generated from passphrase.")
                        .takes_value(true)
                        .multiple_values(true)
                        .number_of_values(3)
                        .required(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("backup", backup_matches)) => {
            if backup_matches.is_present("passphrase") {
                let passphrases: Vec<_> = backup_matches.values_of("passphrase").unwrap().collect();
                let passphrase: String = passphrases.get(0).unwrap().to_string();
                let words: Vec<&str> = passphrase.split(" ").collect();
                let words_count = words.len();
                if words_count != 12 && words_count != 24 {
                    println!("{}", "Passphrase should be 12 or 24 words".red());
                    process::exit(1);
                }

                let passphrase = Passphrase::from_words(&words)
                    .expect(&format!("{}", "Failed to parse passphrase.".red()));

                let shares = get_share(passphrase, 5, 3)
                    .expect(&format!("{}", "Failed to build shares".red()));

                println!("Shares are:");
                for (i, share) in shares.iter().enumerate() {
                    println!(
                        "{}",
                        format!("🔐 Share {} is: {}", i + 1, share.join(" ")).green()
                    );
                }

                return;
            }
        }
        Some(("restore", restore_matches)) => {
            if restore_matches.is_present("share") {
                let shares: Vec<_> = restore_matches.values_of("share").unwrap().collect();
                // check shares
                let mut shares_slices: Vec<Vec<&str>> = Vec::with_capacity(3);
                for share in shares {
                    let words: Vec<&str> = share.split(" ").collect();
                    if words.len() != 13 && words.len() != 25 {
                        println!("{}", "Share should be 13 or 25 words".red());
                        process::exit(1);
                    }
                    shares_slices.push(words);
                }

                let passphrase = restore_from_share(&shares_slices)
                    .expect(&format!("{}", "Failed to restore passphrase.").red());
                let words = passphrase
                    .get_words()
                    .expect(&format!("{}", "Failed to extract words from passphrase.").red());
                println!(
                    "{}",
                    format!("🔑 Original passphrase is: {}", words.join(" ")).green()
                );

                return;
            }
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable
    }
}
