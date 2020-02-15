use std::env::args;
use std::fs::File;
use std::io::{self, Read, Write};

use aes::Aes256;
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;
use rand::Rng;
use sha2::{Digest, Sha512Trunc256};

type AesCfb = Cfb<Aes256>;

#[macro_use]
mod macros {
    macro_rules! map_err {
        ($expr:expr) => {
            ($expr).map_err(|err| format!("line {}: {}", line!(), err.to_string()));
        };
    }
}

const PNG_HEADER: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

struct Chunk {
    length: u32,
    c_type: String,
    data: Vec<u8>,
    crc: u32,
}

impl Chunk {
    fn raw<'a>(&self) -> Vec<u8> {
        let raw_length = u32_to_bytes(self.length);
        let raw_c_type = self.c_type.as_bytes();
        let raw_crc = u32_to_bytes(self.crc);

        let mut data: Vec<u8> = vec![];
        data.append(&mut raw_length.to_vec());
        data.append(&mut raw_c_type.to_vec());
        data.append(&mut self.data.clone());
        data.append(&mut raw_crc.to_vec());

        println!("{:02x?}\n", data);
        data
    }
}

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
        println!(
            "len: {}, c_type: {}, crc: {}",
            chunk.length, chunk.c_type, chunk.crc
        );
        //        dbg!(&chunk.data);
        map_err!(output.write(&chunk.raw()))?;
        chunk = read_chunk(&mut file)?;
    }

    println!("Data to encrypt: ");
    let mut input = String::new();
    let _ = map_err!(std::io::stdin().read_line(&mut input))?;

    let input_data = encrypt_data(input.as_bytes())?;

    println!("Writing data to file...");
    let crypt_chunk = create_chunk(input_data.as_slice(), "crPt");
    map_err!(output.write(&crypt_chunk.raw()))?;

    loop {
        println!(
            "len: {}, c_type: {}, crc: {}",
            chunk.length, chunk.c_type, chunk.crc
        );
        map_err!(output.write(&chunk.raw()))?;
        chunk = match read_chunk(&mut file) {
            Ok(chunk) => chunk,
            Err(_) => break,
        }
    }

    println!("Finished writing data to file.");

    Ok(())
}

fn validate_png(file: &mut File) -> Result<[u8; 8], String> {
    let mut header = [0u8; 8];
    map_err!(file.read_exact(&mut header))?;

    if header == PNG_HEADER.as_ref() {
        return Ok(header);
    }

    Err("Invalid file format".to_string())
}

fn read_chunk(file: &mut File) -> Result<Chunk, String> {
    let mut length_raw = [0u8; 4];
    map_err!(file.read_exact(&mut length_raw))?;

    let length = bytes_to_u32(length_raw);

    let mut c_type_raw = [0u8; 4];
    map_err!(file.read_exact(&mut c_type_raw))?;
    let c_type = unsafe { String::from_utf8_unchecked(c_type_raw.to_vec()) };

    let mut data = vec![0u8; length as usize];
    map_err!(file.read_exact(data.as_mut_slice()))?;

    let mut crc_raw = [0u8; 4];
    map_err!(file.read_exact(&mut crc_raw))?;
    let crc = bytes_to_u32(crc_raw);

    Ok(Chunk {
        length,
        c_type,
        data,
        crc,
    })
}

fn create_chunk(data: &[u8], c_type: &str) -> Chunk {
    let length = data.len() as u32;
    let raw_c_type = c_type.as_bytes();

    let mut data_and_c_type: Vec<u8> = vec![];
    data_and_c_type.append(&mut raw_c_type.to_vec());
    data_and_c_type.append(&mut data.to_vec());

    let crc = crc::crc32::checksum_ieee(data_and_c_type.as_slice());

    Chunk {
        length,
        c_type: c_type.to_string(),
        data: data.to_vec(),
        crc,
    }
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, String> {
    println!("Password: ");
    let mut password = String::new();
    let _ = map_err!(io::stdin().read_line(&mut password))?;

    let mut hasher = Sha512Trunc256::new();
    hasher.input(password);

    encrypt(hasher.result().as_slice(), data)
}

fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let b = base64::encode(data);
    let mut buffer = b.as_bytes().to_vec();

    let iv = rand::thread_rng().gen::<[u8; 16]>();

    let mut cipher = map_err!(AesCfb::new_var(key, &iv))?;
    cipher.encrypt(&mut buffer);

    let mut cipher_text = iv.to_vec();
    cipher_text.append(&mut buffer);

    Ok(cipher_text)
}

fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    bytes[3] as u32 | (bytes[2] as u32) << 8 | (bytes[1] as u32) << 16 | (bytes[0] as u32) << 24
}

fn u32_to_bytes(v: u32) -> [u8; 4] {
    let mut b = [0u8; 4];

    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = v as u8;

    b
}
