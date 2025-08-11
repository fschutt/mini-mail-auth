# Mini Mail Auth

`mini-mail-auth` is a lightweight Rust crate, forked from 
[stalwartlabs/mail-auth](https://github.com/stalwartlabs/mail-auth) 
for developers who "just need to sign an email with a DKIM key".

It is a heavily stripped-down version of the excellent [`mail-auth`](https://crates.io/crates/mail-auth) crate, 
containing only the necessary components for DKIM signing using RSA-SHA256. This results in a minimal 
dependency footprint, ideal for applications where email signing is the only requirement.

## Usage

This crate provides a simple function, `sign_email`, to handle DKIM signing with minimal setup.

```rust
use mini_mail_auth::sign_email;

fn main() {
    let private_key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----".to_string();
    let email_to_sign = concat!(
        "From: bill@example.com\r\n",
        "To: jdoe@example.com\r\n",
        "Subject: TPS Report\r\n",
        "\r\n",
        "I'm going to need those TPS reports ASAP."
    );

    let signed_email = sign_email(
        email_to_sign,
        "example.com",
        "default",
        &private_key,
    );

    println!("{}", signed_email);
}
```
