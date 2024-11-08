mod config;
mod content_description;
mod encryption;

use crate::config::MailConfig;
use crate::content_description::ContentDescription;
use crate::encryption::encrypt_data;
use anyhow::anyhow;
use clap::Parser;
use handlebars::Handlebars;
use lettre::message::header::{Header, Headers};
use lettre::message::{header, Mailbox, Mailboxes, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::SUBMISSION_PORT;
use lettre::{SmtpTransport, Transport};
use sequoia_openpgp::crypto::KeyPair;
use sequoia_openpgp::packet::prelude::SignatureBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Message, Recipient, Signer};
use sequoia_openpgp::types::{HashAlgorithm, SignatureType};
use sequoia_openpgp::Cert;
use std::collections::VecDeque;
use std::io::Write;
use std::str::FromStr;
use tracing_subscriber::filter::LevelFilter;

/// Simple program to manage certificate for our root CA
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// The name of the sender (eg: John Adams)
    #[arg(short = 'n', long)]
    pub from_name: String,
    /// The email of the sender (eg: john.adams@company.tld)
    #[arg(short = 'e', long)]
    pub from_email: String,
    /// The name of the receiver (eg: Alice Jones)
    #[arg(short = 't', long)]
    pub to_name: String,
    /// The email of the receiver (eg: alice.jones@company.tld)
    #[arg(short = 'm', long)]
    pub to_email: String,
    /// The username used to log in to the SMTP server, leave blank to default to email
    #[arg(short, long)]
    pub username: Option<String>,
    /// The address of the mail server
    #[arg(short, long, default_value = "email.somewhere.com")]
    pub server: String,
    /// The port if different than the SMTP default
    #[arg(short, long, default_value_t = SUBMISSION_PORT)]
    pub port: u16,
    /// Log level to be considered:
    ///
    ///  * 0: off
    ///  * 1: error
    ///  * 2: warn
    ///  * 3: info
    ///  * 4: debug
    ///  * 5: trace
    #[arg(short, long, default_value = "error")]
    pub log_level: LevelFilter,
}

macro_rules! load_key {
    ($keypairs:ident, $recipients:ident, $keys:ident) => {
        let policy = StandardPolicy::new();
        let mut certs = vec![];
        for key in $keys {
            certs.push(Cert::from_bytes(key.as_ref())?);
        }
        for cert in &certs {
            for ka in cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
            {
                $recipients.push(Recipient::new(ka.key().keyid(), ka.key()));
            }

            for ka in cert
                .keys()
                .secret()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
            {
                let gpg_password =
                    rpassword::prompt_password(format!("GPG password for {}: ", ka.key().keyid()))?;
                if let Ok(key) = ka.key().clone().decrypt_secret(&gpg_password.into()) {
                    if let Ok(keypair) = key.into_keypair() {
                        $keypairs.push_back(keypair);
                    }
                } else {
                    eprintln!("Wrong password");
                }
            }
        }
    };
}

fn create_simple_message(message: &[u8], html: bool) -> SinglePart {
    SinglePart::builder()
        .content_type(if html {
            header::ContentType::TEXT_HTML
        } else {
            header::ContentType::TEXT_PLAIN
        })
        .header(header::ContentTransferEncoding::Base64)
        .body(message.to_vec())
}

fn create_boundary() -> String {
    format!(
        "------------{}",
        std::iter::repeat_with(fastrand::alphanumeric)
            .take(25)
            .collect::<String>()
    )
}

struct MessageInfo<'a, 'b, 'c, 'd> {
    message_id: &'a str,
    subject: &'b str,
    to: &'c Mailboxes,
    from: &'d Mailboxes,
}

fn adjust_protected_header(headers: &mut Headers) -> anyhow::Result<()> {
    let content_type: header::ContentType = headers.get().ok_or(anyhow!("Missing content type"))?;
    // Small dance to print the header
    let mut temp_header = Headers::new();
    temp_header.set(content_type);
    let content_type = temp_header.to_string().split("\r\n").collect::<String>();

    // Add the protected header
    let (name, value) = content_type
        .trim()
        .split_once(": ")
        .ok_or(anyhow!("Missing delimiter"))?;
    if name != "Content-Type" {
        return Err(anyhow!("Invalid header {name}, not Content-Type"));
    }
    let value = format!("{}; protected-headers=\"v1\"", value.trim());
    headers.set(header::ContentType::parse(value.as_str())?);
    Ok(())
}

fn create_secret_message(
    info: MessageInfo,
    html: bool,
    message: &[u8],
) -> anyhow::Result<MultiPart> {
    let boundary = create_boundary();
    let mut mixed = MultiPart::mixed()
        .boundary(boundary)
        .header(header::Subject::parse(info.subject).map_err(|_| anyhow!("Invalid subject"))?)
        .header(header::From::from(info.from.clone()))
        .header(header::To::from(info.to.clone()))
        .header(header::MessageId::from(info.message_id.to_string()))
        .singlepart(create_simple_message(message, html));

    adjust_protected_header(mixed.headers_mut())?;
    Ok(mixed)
}
const PGP_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----";
fn create_signature(mut keypairs: VecDeque<KeyPair>, mixed: &MultiPart) -> anyhow::Result<String> {
    let mut secret_message = String::from_utf8(mixed.formatted())?;
    // remove LF
    secret_message.pop();
    // remove CR
    secret_message.pop();

    let mut sink = vec![];
    let keypair = keypairs.pop_front().ok_or(anyhow!("No key for signing"))?;
    let mut signer = Signer::with_template(
        Message::new(&mut sink),
        keypair,
        SignatureBuilder::new(SignatureType::Binary),
    );
    for kp in keypairs {
        signer = signer.add_signer(kp);
    }
    let mut signer = signer
        .cleartext()
        .hash_algo(HashAlgorithm::SHA256)?
        .build()?;
    signer.write(secret_message.as_ref())?;
    signer.finalize()?;

    let signature = String::from_utf8_lossy(sink.as_slice());
    let needle = signature
        .find(PGP_SIGNATURE)
        .ok_or(anyhow!("Missing signature"))?;
    let (_, r) = signature.split_at(needle);
    Ok(r.to_string())
}

fn create_signed_msg(
    keypairs: VecDeque<KeyPair>,
    info: MessageInfo,
    html: bool,
    message: &[u8],
) -> anyhow::Result<MultiPart> {
    let secret_message = create_secret_message(info, html, message)?;
    let signature = create_signature(keypairs, &secret_message)?;

    Ok(MultiPart::signed(
        "application/pgp-signature".to_string(),
        "pgp-sha256".to_string(),
    )
    .boundary(create_boundary())
    .multipart(secret_message)
    .singlepart(
        SinglePart::builder()
            .header(
                header::ContentType::parse(
                    "application/pgp-signature; name=\"OpenPGP_signature.asc\"",
                )
                .unwrap(),
            )
            .header(ContentDescription::parse("OpenPGP digital signature").unwrap())
            .header(
                header::ContentDisposition::parse("attachment; filename=\"OpenPGP_signature\"")
                    .unwrap(),
            )
            .body(signature),
    ))
}

fn create_message_id(server_address: &str) -> String {
    format!(
        "<{}@{}>",
        std::iter::repeat_with(fastrand::alphanumeric)
            .take(36)
            .collect::<String>(),
        server_address
    )
}

fn create_message_from<V: Into<Vec<u8>>>(encrypted: V) -> MultiPart {
    MultiPart::encrypted("application/pgp-encrypted".to_owned())
        .boundary(create_boundary())
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::parse("application/pgp-encrypted").unwrap())
                .header(ContentDescription::parse("PGP/MIME version identification").unwrap())
                .body(String::from("Version: 1\n")),
        )
        .singlepart(
            SinglePart::builder()
                .header(
                    header::ContentType::parse("application/octet-stream; name=\"encrypted.asc\"")
                        .unwrap(),
                )
                .header(header::ContentDisposition::inline_with_name(
                    "encrypted.asc",
                ))
                .header(header::ContentTransferEncoding::Binary)
                .header(ContentDescription::parse("OpenPGP encrypted message").unwrap())
                .body(encrypted.into()),
        )
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(cli.log_level)
        .init();

    let mut recipients = vec![];
    let mut keypairs = VecDeque::new();
    /* Load keys*/
    let key_0 = include_bytes!("../Public.asc");
    let key_1 = include_bytes!("../Secret.asc");
    let keys = [key_0.as_slice(), key_1.as_slice()];
    load_key!(keypairs, recipients, keys);
    /* Load keys*/

    /* Template */
    let mut reg = Handlebars::new();
    reg.register_template_file("mail", "html_template.hbs")?;
    let data = reg.render(
        "mail",
        &serde_json::json!({"name":"test","prefix":"test.test"}),
    )?;
    // let data = "data";
    /* Template */

    let subject = "New certificates";
    let to = Mailboxes::from(Mailbox::from_str(
        format!("{} <{}>", cli.to_name, cli.to_email).as_str(),
    )?);

    let config = MailConfig::from_string(format!("{} <{}>", cli.from_name, cli.from_email))?;
    let msg_id = create_message_id(cli.server.as_str());

    let info = MessageInfo {
        message_id: msg_id.as_str(),
        subject,
        to: &to,
        from: config.from(),
    };

    let signed_msg = create_signed_msg(keypairs, info, true, data.as_bytes())?.formatted();

    let part = create_message_from(encrypt_data(signed_msg, recipients)?);

    let mail_password = rpassword::prompt_password("Mail password: ")?;
    let creds = Credentials::new(
        cli.username.unwrap_or(cli.from_email.clone()),
        mail_password,
    );
    let mailer = SmtpTransport::starttls_relay(&*cli.server)?
        .port(cli.port)
        .credentials(creds)
        .build();

    let email = config.create_mail_multipart(to, "...", Some(msg_id), part)?;
    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {:?}", e),
    }
    Ok(())
}
