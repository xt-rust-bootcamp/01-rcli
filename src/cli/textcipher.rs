use std::{fmt, path::PathBuf, str::FromStr};

use clap::Parser;

use super::{verify_file, verify_path};

#[derive(Debug, Parser)]
pub enum TextCipherSubCommand {
    Generate(KeyGenerateOpts),
    #[command(about = "encrypt a plaintext with a private/session key and return a ciphertext")]
    Encrypt(EncryptOpts),
    #[command(about = "decrypt the ciphertext and return the plaintext")]
    Decrypt(DecryptOpts),
}

#[derive(Debug, Parser)]
pub struct KeyGenerateOpts {
    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_cipher_format)]
    pub format: TextCipherFormat,
    #[arg(short, long, value_parser = verify_path)]
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
pub struct EncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(short, long, value_parser = verify_file)]
    pub nonce: String,
    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_cipher_format)]
    pub format: TextCipherFormat,
}

#[derive(Debug, Parser)]
pub struct DecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(short, long, value_parser = verify_file)]
    pub nonce: String,
    #[arg(long)]
    pub ciphertext: String,
    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_cipher_format)]
    pub format: TextCipherFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum TextCipherFormat {
    Chacha20poly1305,
}

fn parse_text_cipher_format(format: &str) -> Result<TextCipherFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextCipherFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20poly1305" => Ok(TextCipherFormat::Chacha20poly1305),
            _ => Err(anyhow::anyhow!("Invalid format")),
        }
    }
}

impl From<TextCipherFormat> for &'static str {
    fn from(format: TextCipherFormat) -> Self {
        match format {
            TextCipherFormat::Chacha20poly1305 => "chacha20poly1305",
        }
    }
}

impl fmt::Display for TextCipherFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}
