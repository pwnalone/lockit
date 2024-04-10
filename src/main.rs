use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Parser, ValueEnum};
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence};
use ring::pbkdf2;
use ring::rand::{self, SecureRandom};
use tempfile::{NamedTempFile, PersistError};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The file to encrypt/decrypt
    file: PathBuf,

    /// Encrypt file (default)
    #[arg(group = "action", short, long)]
    encrypt: bool,

    /// Decrypt file
    #[arg(group = "action", short, long)]
    decrypt: bool,

    /// Key derivation function
    #[arg(long, value_enum, default_value_t = Kdf::Pbkdf2HmacSha512)]
    kdf: Kdf,

    /// Number of iterations for the key derivation function
    ///
    /// Defaults:
    ///
    /// pbkdf2-hmac-sha256 => 600,000
    /// pbkdf2-hmac-sha384 => 400,000
    /// pbkdf2-hmac-sha512 => 200,000
    #[arg(short, long, verbatim_doc_comment)]
    iterations: Option<NonZeroU32>,

    /// Cipher to use for encryption/decryption
    #[arg(long, value_enum, default_value_t = Cipher::Aes256Gcm)]
    cipher: Cipher,
}

/// A key derivation function (KDF).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Kdf {
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

/// A cryptographic cipher.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
}

/// A KDF config.
struct KdfConfig<'a> {
    alg: pbkdf2::Algorithm,
    iterations: NonZeroU32,
    pass: &'a [u8],
    salt: &'a [u8],
    len: usize,
}

/// A cryptographic cipher config.
struct CipherConfig<'a> {
    alg: &'static aead::Algorithm,
    key: &'a [u8],
    random_bytes: [u8; 16],
}

/// An incrementing nonce counter.
struct NonceCounter {
    nonce: [u8; 12],
}

impl TryFrom<&[u8]> for NonceCounter {
    type Error = ring::error::Unspecified;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 12 {
            Err(ring::error::Unspecified)
        } else {
            let mut nonce = [0; 12];
            nonce.copy_from_slice(value);
            Ok(Self { nonce })
        }
    }
}

impl NonceSequence for NonceCounter {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.nonce);

        // Get the next permutation of the nonce as if it were a 96-bit little-endian integer.
        //
        // Because the size of the nonce is fixed, the compiler will unroll the loop and
        // transform it into 12 "add-with-carry" intrinsic operations.
        //
        // With modern processors' pipelines, this is much faster than bailing out of the loop
        // early when there is no carry.
        let mut carry = 1;
        for x in self.nonce.iter_mut() {
            let (v, overflow) = x.overflowing_add(carry);
            carry = overflow as u8;
            *x = v;
        }

        Ok(nonce)
    }
}

#[derive(Debug, Error)]
enum EncryptError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Failed to persist encryption: {0}")]
    Fs(#[from] PersistError),
    #[error("Failed to encrypt file")]
    Crypto,
}

#[derive(Debug, Error)]
enum DecryptError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Failed to persist decryption: {0}")]
    Fs(#[from] PersistError),
    #[error("Failed to decrypt file")]
    Crypto,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Do a quick check that a valid file was specified.
    //
    // There are no TOCTOU issues here. If the file is changed between now and when we perform the
    // encryption/decryption, then an error will likely occur. This is just a courtesy to the user.
    let meta = fs::metadata(&args.file)?;
    if !meta.is_file() {
        eprintln!("Error: <FILE> must be a regular file");
        process::exit(1);
    }
    if meta.permissions().readonly() {
        eprintln!("Error: <FILE> must be writeable by the current user");
        process::exit(1);
    }

    // Prompt the user twice for their password and confirm they are the same.
    // The `Zeroizing` wrapper ensures the password is zeroed on drop.
    let pass1 = Zeroizing::new(rpassword::prompt_password("Enter password: ")?);
    let pass2 = Zeroizing::new(rpassword::prompt_password("Confirm: ")?);
    if pass1 != pass2 {
        eprintln!("Error: Passwords do not match!");
        process::exit(1);
    }

    // The encryption/decryption key is derived from the user's password and a random 16-byte salt.
    // The first 12 bytes of the salt are also used as the initial nonce value for the cipher
    // algorithm. This means we only need to store the salt to be able to decrypt the file later,
    // reducing the final size of the encrypted file by 12 bytes.
    //
    // This should not impact the security of the encryption, as the only requirement for the nonce
    // is that it be unique with respect to the key.
    let mut bytes = [0; 16];

    if args.decrypt {
        // Read the random salt/nonce from the beginning of the encrypted file.
        File::open(&args.file)?.read_exact(&mut bytes)?;
        // Otherwise, securely generate one.
    } else if let Err(err) = rand::SystemRandom::new().fill(&mut bytes) {
        eprintln!("Error: Failed to generate random bytes: {err}");
        process::exit(1);
    }

    let block_size = match args.cipher {
        Cipher::Aes128Gcm => aead::AES_128_GCM.key_len(),
        Cipher::Aes256Gcm => aead::AES_256_GCM.key_len(),
    };

    let kdf_config = match args.kdf {
        Kdf::Pbkdf2HmacSha256 => KdfConfig {
            alg: pbkdf2::PBKDF2_HMAC_SHA256,
            iterations: args.iterations.or(NonZeroU32::new(600_000)).unwrap(),
            pass: pass1.as_bytes(),
            salt: &bytes,
            len: block_size,
        },
        Kdf::Pbkdf2HmacSha384 => KdfConfig {
            alg: pbkdf2::PBKDF2_HMAC_SHA384,
            iterations: args.iterations.or(NonZeroU32::new(400_000)).unwrap(),
            pass: pass1.as_bytes(),
            salt: &bytes,
            len: block_size,
        },
        Kdf::Pbkdf2HmacSha512 => KdfConfig {
            alg: pbkdf2::PBKDF2_HMAC_SHA512,
            iterations: args.iterations.or(NonZeroU32::new(200_000)).unwrap(),
            pass: pass1.as_bytes(),
            salt: &bytes,
            len: block_size,
        },
    };

    // Generate an encryption/decryption key from the password and salt.
    let key = Zeroizing::new(genkey(kdf_config));

    // Do not leave the password hanging around in memory.
    drop(pass1);
    drop(pass2);

    let cipher_config = match args.cipher {
        Cipher::Aes128Gcm => CipherConfig {
            alg: &aead::AES_128_GCM,
            key: &key,
            random_bytes: bytes,
        },
        Cipher::Aes256Gcm => CipherConfig {
            alg: &aead::AES_256_GCM,
            key: &key,
            random_bytes: bytes,
        },
    };

    // Perform the encryption or decryption.
    if args.decrypt {
        decrypt(&args.file, cipher_config)?;
    } else {
        encrypt(&args.file, cipher_config)?;
    }

    Ok(())
}

fn genkey(config: KdfConfig) -> Vec<u8> {
    let mut key = vec![0; config.len];
    pbkdf2::derive(
        config.alg,
        config.iterations,
        config.salt,
        config.pass,
        &mut key,
    );
    key
}

fn encrypt(file: &Path, config: CipherConfig) -> Result<(), EncryptError> {
    // We will encrypt to a temporary file first and then replace the plaintext file to prevent
    // data loss in the case that an error occurs.
    let mut tmp = NamedTempFile::new()?;

    let mut buf = fs::read(file)?;

    let nonce_counter = NonceCounter::try_from(&config.random_bytes[..12]).unwrap();
    let raw_key = aead::UnboundKey::new(config.alg, config.key).unwrap();
    let mut key = aead::SealingKey::new(raw_key, nonce_counter);

    // We use `seal_in_place_separate_tag()` here as opposed to `seal_in_place_append_tag()` to
    // avoid a potential reallocation/copy of the vector, containing the bytes we are trying to
    // encrypt.
    //
    // This prevents sensitive data from being left around in memory.
    let tag = key
        .seal_in_place_separate_tag(Aad::empty(), &mut buf)
        .or(Err(EncryptError::Crypto))?;

    // Format: [salt/nonce] || [encrypted data] || [AE tag]
    tmp.write_all(&config.random_bytes[..])?;
    tmp.write_all(&buf)?;
    tmp.write_all(tag.as_ref())?;

    // Replace the plaintext file.
    tmp.persist(file)?;

    Ok(())
}

fn decrypt(file: &Path, config: CipherConfig) -> Result<(), DecryptError> {
    // We will decrypt to a temporary file first and then replace the encrypted file to prevent
    // data loss in the case that an error occurs.
    let mut tmp = NamedTempFile::new()?;

    let mut buf = fs::read(file)?;

    let nonce_counter = NonceCounter::try_from(&config.random_bytes[..12]).unwrap();
    let raw_key = aead::UnboundKey::new(config.alg, config.key).unwrap();
    let mut key = aead::OpeningKey::new(raw_key, nonce_counter);

    // Decrypt the file and verify the AE tag to confirm the decryption's integrity.
    let buf = key
        .open_within(Aad::empty(), &mut buf, 16..)
        .or(Err(DecryptError::Crypto))?;

    tmp.write_all(buf)?;

    // Replace the encrypted file.
    tmp.persist(file)?;

    Ok(())
}
