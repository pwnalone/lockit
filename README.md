# Lockit

Lockit is a small, command line program to password protect your files with strong encryption.

## Install

```sh
$ cargo install lockit
```

## Usage

Display help.

```sh
$ lockit -h  # Use --help for the long help message.
```

Encrypt a file.

```sh
$ lockit -e secret.txt
```

Decrypt a file.

```sh
$ lockit -d secret.txt
```

Increase the number of hashing iterations of the KDF's HMAC function. This increases the
computational cost of cracking your password. The same iteration count needs to be passed to Lockit
when decrypting the file.

```sh
$ lockit -e -i 1000000 secret.txt
```

## Technical Details

By default, Lockit applies [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) with 200,000 iterations of
[HMAC-SHA512](https://en.wikipedia.org/wiki/HMAC) to your password and a random 16-byte salt to
generate a key, which it then uses to encrypt the file using
[AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [Galois/Counter
Mode (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode). This mode of operation provides both
confidentiality (i.e. the data cannot be read) and integrity (i.e. the data cannot be covertly
tampered with).

## Disclaimer

This is the work of a Rust noob, which I am sharing here as a potential learning resource for others
and to show off some of my newfound Rust skills.

I recently finished reading [The Rust Programming Language](https://doc.rust-lang.org/book/) and was
looking for a project to help me get more comfortable writing software in Rust and making use of the
available [crates](https://crates.io/). I tried a few of the many
[Build Your Own X](https://build-your-own-x.vercel.app/) tutorials, but found that I was doing a lot
of copy-pasting of the code samples without actually doing much thinking for myself. Therefore, I
wasn't getting the benefit of figuring out how to _design_ Rust software.

I eventually decided to take a break from these follow-along style tutorials and to try to implement
something, myself, that I thought would be fun and interesting. Cryptography being one of my primary
interests, I chose to write a file encryption/decryption utility!

If you are interested in trying this out for yourself, then here is my proposal for you: Do NOT read
the source code in this repository. Implement your own version of this application, and, once you
have a product that you are satisfied with, feel free to compare my code to what you wrote, keeping
in mind that your solution may very well be better.

This is roughly the order in which I implemented the various components.

1. Command line option/argument parsing
2. Reading a password from the terminal
3. Turning the password into a key
4. Reading a file into memory
5. Writing a file to disk
6. Encrypting data
7. Decrypting data

In my implementation (~300 LoC) I used the following crates, but I encourage you to [search for
alternatives](https://crates.io/).

| Crate                                           | Description                                   |
| :---------------------------------------------: | :-------------------------------------------: |
| [anyhow](https://crates.io/crates/anyhow)       | Improved error messages with optional context |
| [clap](https://crates.io/crates/clap)           | Command line argument parsing                 |
| [ring](https://crates.io/crates/ring)           | Cryptographic primitives                      |
| [rpassword](https://crates.io/crates/rpassword) | Read passwords from the console               |
| [tempfile](https://crates.io/crates/tempfile)   | Temporary files to help prevent data loss     |
| [thiserror](https://crates.io/crates/thiserror) | Easily create custom error types              |
| [zeroize](https://crates.io/crates/zeroize)     | Securely clear secrets from memory            |

Finding, evaluating, and comparing the libraries you have at your disposal in order to choose the
one that is right for your use case is an important part of software development. And so is reading
documentation, which I hope you will get lots of practice doing when figuring out how to use your
chosen crates.
