use sequoia_openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message, Recipient};
use std::io::Write;
pub fn encrypt_data<'a, B: AsRef<[u8]>, R>(data: B, recipients: R) -> anyhow::Result<Vec<u8>>
where
    R: IntoIterator,
    R::Item: Into<Recipient<'a>>,
{
    let mut sink = vec![];
    let message = Message::new(&mut sink);
    let armorer = Armorer::new(message).build()?;
    let encryptor = Encryptor2::for_recipients(armorer, recipients).build()?;
    let mut w = LiteralWriter::new(encryptor).build()?;
    w.write_all(data.as_ref())?;
    w.finalize()?;

    Ok(sink)
}

#[test]
fn test_load_key() {
    let key = include_bytes!("../Public.asc");
    load_key(key);
}
