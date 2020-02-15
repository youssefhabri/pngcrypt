#[macro_use]
extern crate pngcrypt;

use pngcrypt::*;
use std::env::args;
use std::fs::File;
use std::io::{self, Read, Write};

fn main() -> Result<(), String> {
    let input = match args().nth(1) {
        Some(filename) => filename,
        None => {
            return Err("Input file is required!".to_string());
        }
    };

    let output = match args().nth(2) {
        Some(filename) => filename,
        None => {
            return Err("Output file is required!".to_string());
        }
    };

    let mut input = map_err!(File::open(input.clone()))?;

    let header = validate_png(&mut input)?;

    let mut output = map_err!(File::create(output))?;

    let mut chunk = read_chunk(&mut input)?;

    while &chunk.c_type != CHUNK_NAME {
        chunk = read_chunk(&mut input)?;
    }

    let data = decrypt_data(&chunk.data)?;

    println!("Writing data to file...");

    let _ = map_err!(output.write(&data))?;

    println!("Finished writing data to file.");

    Ok(())
}
