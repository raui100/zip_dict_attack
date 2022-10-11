use std::io::{Cursor, Read};

use clap::Parser;
use indicatif::{HumanCount, HumanDuration, ParallelProgressIterator, ProgressStyle};
use rayon::prelude::*;

/// Tries to determine the password of a ZIP file via dictionary attack
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path to the dictionary file
    dict: std::path::PathBuf,

    /// Path to the ZIP file
    zip: std::path::PathBuf,

    /// Display a progressbar
    #[arg(short, long)]
    progress: bool,
}

fn main() {
    // Measures the total runtime
    let start = std::time::Instant::now();

    // Parses the arguments from the command line
    let args = Args::parse();
    // Reading in the password dictionary
    let dict_string = std::fs::read_to_string(&args.dict).unwrap_or_else(|_| {
        panic!(
            "Failed reading the dictionary file: {}",
            args.dict.display()
        )
    });
    let dict: Vec<&str> = dict_string.lines().collect();

    // Reading the ZIP file into RAM
    let zip_file = std::fs::read(&args.zip)
        .unwrap_or_else(|_| panic!("Failed reading the ZIP file: {}", args.zip.display()));

    // Trying all passwords that are provided via the password dictionary until a valid password is found
    let password = match args.progress {
        true => {
            // Styling the progressbar
            let progress_style = ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {spinner} {pos:>7}/{len:7} throughput:{per_sec} (eta:{eta})")
                .expect("Failed to create progress style");

            dict.par_iter()
                .enumerate()
                .progress_with_style(progress_style)
                .find_map_any(|(ind, s)| decrypt(ind, s, &zip_file))
        }
        false => dict
            .par_iter()
            .enumerate()
            .find_map_any(|(ind, s)| decrypt(ind, s, &zip_file)),
    };

    // Stops measuring the runtime
    let stop = start.elapsed();

    //
    match password {
        None => {
            println!("Password couldn't be found in dict");
            let speed = HumanCount(((dict.len() as f64) / stop.as_secs_f64()) as u64);
            println!("Average speed: {speed} passwords/second");
        }
        Some((ind, psw)) => {
            println!("Passwort: {psw}");
            let speed = HumanCount(((ind as f64) / stop.as_secs_f64()) as u64);
            println!("Average speed: {speed} passwords/second");
        }
    }
    println!("Duration: {}", HumanDuration(stop));
}

fn decrypt<'a>(ind: usize, password: &'a str, zip_file: &[u8]) -> Option<(usize, &'a str)> {
    let cursor = Cursor::new(zip_file);
    let mut archive = zip::ZipArchive::new(cursor).expect("Failed opening ZIP archive");
    let result = archive.by_index_decrypt(0, password.as_bytes());

    match result {
        Ok(Ok(mut zip)) => {
            let mut buffer = Vec::with_capacity(zip.size() as usize);
            match zip.read_to_end(&mut buffer) {
                Err(_) => None, // False positive due to weakness of the ZipCrypto algorithm
                Ok(_) => Some((ind, password)),
            }
        }
        _ => None,
    }
}
