use crate::{
    cipher_text_key_generate, get_content, get_reader, process_text_decrypt, process_text_encrypt,
    CmdExector,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::{fmt, path::PathBuf, str::FromStr};
use tokio::fs;

use super::{verify_file, verify_path};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum TextCipherSubCommand {
    Generate(CipherKeyGenerateOpts),
    #[command(about = "encrypt a plaintext with a private/session key and return a ciphertext")]
    Encrypt(EncryptOpts),
    #[command(about = "decrypt the ciphertext and return the plaintext")]
    Decrypt(DecryptOpts),
}

#[derive(Debug, Parser)]
pub struct CipherKeyGenerateOpts {
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

impl CmdExector for EncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let nonce = get_content(&self.nonce)?;
        let encrypt_text = process_text_encrypt(&mut reader, &key, &nonce, self.format)?;
        // base64 output
        let encoded = URL_SAFE_NO_PAD.encode(encrypt_text);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExector for DecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = get_content(&self.key)?;
        let nonce = get_content(&self.nonce)?;
        let decoded = URL_SAFE_NO_PAD.decode(&self.ciphertext)?;
        let plaintext = process_text_decrypt(&key, &nonce, &decoded, self.format)?;
        let plaintext = String::from_utf8(plaintext)?;
        println!("Decrypted text: {}", plaintext);
        Ok(())
    }
}

impl CmdExector for CipherKeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = cipher_text_key_generate(self.format)?;
        for (k, v) in key {
            fs::write(self.output_path.join(k), v).await?;
        }
        Ok(())
    }
}

// impl CmdExector for TextCipherSubCommand {
//     async fn execute(self) -> anyhow::Result<()> {
//         match self {
//             TextCipherSubCommand::Encrypt(opts) => opts.execute().await,
//             TextCipherSubCommand::Decrypt(opts) => opts.execute().await,
//             TextCipherSubCommand::Generate(opts) => opts.execute().await,
//         }
//     }
// }
