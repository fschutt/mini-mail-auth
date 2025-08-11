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

    println!("ok!");
    
    // Sign the email using the mini-mail-auth crate.
    let signed_email_mini_mail_auth =
        mini_mail_auth::sign_email(email, domain, selector, &private_key);

    // Compare the two signatures.
    println!("--- mail-auth output ---");
    println!("{}", signed_email_mail_auth);
    println!("--- mini-mail-auth output ---");
    println!("{}", signed_email_mini_mail_auth);

    // Normalize the signatures by removing the timestamp and signature fields.
    let signed_email_mail_auth = normalize_signature(&signed_email_mail_auth);
    let signed_email_mini_mail_auth = normalize_signature(&signed_email_mini_mail_auth);

    assert_eq!(
        signed_email_mail_auth, signed_email_mini_mail_auth,
        "The signatures from mail-auth and mini-mail-auth do not match!"
    );

    println!("\n✅ Signatures match!");
}

fn normalize_signature(signed_email: &str) -> String {
    use regex::Regex;
    // This regex removes the `b=` (signature) and `t=` (timestamp) tags from the DKIM-Signature header.
    let re_b = Regex::new(r"\s*b=([A-Za-z0-9+/= \t\r\n]+);").unwrap();
    let re_t = Regex::new(r"\s*t=\d+;").unwrap();

    let without_b = re_b.replace_all(signed_email, "");
    re_t.replace_all(&without_b, "").to_string()
}
