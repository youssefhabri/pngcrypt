use pngcrypt::*;
use std::env::args;
use std::fs::File;
use std::io::{self, Read, Write};

fn main() -> Result<(), String> {
    let filename = match args().nth(1) {
        Some(filename) => filename,
        None => {
            return Err("A file name is required!".to_string());
        }
    };

    let mut file = map_err!(File::open(filename.clone()))?;

    let header = validate_png(&mut file)?;

    let mut output = map_err!(File::create(format!("encrypted-{}", filename)))?;

    map_err!(output.write(&header))?;

    let mut chunk = read_chunk(&mut file)?;

    while &chunk.c_type != "IDAT" {
        map_err!(output.write(&chunk.raw()))?;
        chunk = read_chunk(&mut file)?;
    }

    println!("Data to encrypt: ");
    let mut input = String::new();
    let _ = map_err!(std::io::stdin().read_line(&mut input))?;

    let input_data = encrypt_data(input.as_bytes())?;

    println!("Writing data to file...");
    let crypt_chunk = create_chunk(input_data.as_slice(), CHUNK_NAME);
    map_err!(output.write(&crypt_chunk.raw()))?;

    loop {
        map_err!(output.write(&chunk.raw()))?;
        chunk = match read_chunk(&mut file) {
            Ok(chunk) => chunk,
            Err(_) => break,
        }
    }

    println!("Finished writing data to file.");

    Ok(())
}
