fn main() {
    // Read the private key from the file generated in the previous step.
    let private_key = std::fs::read_to_string("private_key.pem")
        .expect("Failed to read private_key.pem. Make sure it's in the mini-mail-auth directory.");

    // Define a sample email.
    let email = "From: \"Joe Bloggs\" <joe@example.com>\r\n\
                 To: \"John Doe\" <john@example.com>\r\n\
                 Subject: Test Email\r\n\
                 \r\n\
                 This is a test email.";

    // Define the domain and selector for DKIM signing.
    let domain = "example.com";
    let selector = "default";

    // Sign the email using the original mail-auth crate.
    let signed_email_mail_auth = {
        use mail_auth::common::crypto::{RsaKey, Sha256};
        use mail_auth::common::headers::HeaderWriter;
        use mail_auth::dkim::DkimSigner;

        let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(&private_key).unwrap();
        let signature_rsa = DkimSigner::from_key(pk_rsa)
            .domain(domain)
            .selector(selector)
            .headers(["From", "To", "Subject"])
            .sign(email.as_bytes())
            .unwrap();

        format!("{}{}", signature_rsa.to_header(), email)
    };

    // Sign the email using the mini-mail-auth crate.
    let signed_email_mini_mail_auth =
        mini_mail_auth::sign_email(email, domain, selector, &private_key);

    // Compare the two signatures.
    println!("--- mail-auth output ---");
    println!("{}", signed_email_mail_auth);
    println!("--- mini-mail-auth output ---");
    println!("{}", signed_email_mini_mail_auth);

    assert_eq!(
        signed_email_mail_auth, signed_email_mini_mail_auth,
        "The signatures from mail-auth and mini-mail-auth do not match!"
    );

    println!("\n✅ Signatures match!");
}
