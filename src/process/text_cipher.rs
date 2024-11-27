use crate::TextCipherFormat;
use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};

use std::{collections::HashMap, io::Read};

pub trait TextEncryptor {
    // TextEncryptor could encrypt any input data
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextDecrypter {
    // TextDecrypter could decrypt any input data
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub struct Chacha20poly1305Cipher {
    key: Key,
    nonce: Nonce,
}

impl TextEncryptor for Chacha20poly1305Cipher {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let cipher = ChaCha20Poly1305::new(&self.key);
        let ciphertext = cipher.encrypt(&self.nonce, buf.as_ref());
        match ciphertext {
            Ok(ciphertext) => Ok(ciphertext),
            _ => Err(anyhow::anyhow!(
                "Failed to encrypt data with ChaCha20Poly1305"
            )),
        }
    }
}

impl TextDecrypter for Chacha20poly1305Cipher {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);

        let plaintext = cipher.decrypt(&self.nonce, ciphertext);
        match plaintext {
            Ok(plaintext) => Ok(plaintext),
            _ => Err(anyhow::anyhow!(
                "Failed to decrypt data with ChaCha20Poly1305"
            )),
        }
    }
}

impl Chacha20poly1305Cipher {
    pub fn try_new(key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let nonce = nonce.as_ref();
        let nonce = (&nonce[..12]).try_into()?;

        Ok(Self::new(key, nonce))
    }

    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let key = Key::clone_from_slice(key);
        let nonce = Nonce::clone_from_slice(nonce);
        Self { key, nonce }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut map = HashMap::new();
        map.insert("chacha20poly1305key.txt", key.to_vec());
        map.insert("chacha20poly1305nonce.txt", nonce.to_vec());

        Ok(map)
    }
}

pub fn process_text_encrypt(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    nonce: &[u8],
    format: TextCipherFormat,
) -> Result<Vec<u8>> {
    let encrypher: Box<dyn TextEncryptor> = match format {
        TextCipherFormat::Chacha20poly1305 => {
            Box::new(Chacha20poly1305Cipher::try_new(key, nonce)?)
        }
    };

    encrypher.encrypt(reader)
}

pub fn process_text_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    format: TextCipherFormat,
) -> Result<Vec<u8>> {
    let decrypher: Box<dyn TextDecrypter> = match format {
        TextCipherFormat::Chacha20poly1305 => {
            Box::new(Chacha20poly1305Cipher::try_new(key, nonce)?)
        }
    };
    decrypher.decrypt(ciphertext)
}

pub fn cipher_text_key_generate(
    format: TextCipherFormat,
) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextCipherFormat::Chacha20poly1305 => Chacha20poly1305Cipher::generate(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = include_bytes!("../../fixtures/chacha20poly1305key.txt");
    const NONCE: &[u8] = include_bytes!("../../fixtures/chacha20poly1305nonce.txt");

    #[test]
    fn test_process_text_crypt() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextCipherFormat::Chacha20poly1305;
        let encrypt_text = process_text_encrypt(&mut reader, KEY, NONCE, format)?;

        let decrypt_text = process_text_decrypt(KEY, NONCE, &encrypt_text, format)?;
        assert_eq!("hello".as_bytes(), decrypt_text);
        Ok(())
    }
}
