use lettre::message::header::ContentType;
use lettre::message::{IntoBody, Mailbox, Mailboxes, MessageBuilder, MultiPart};
use lettre::Message;
use std::str::FromStr;

pub struct MailConfig {
    from: Mailboxes,
    reply_to: Mailboxes,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            from: Mailbox::from_str("Robot <someone@somewhere.com>")
                .expect("Valid email")
                .into(),
            reply_to: Mailbox::from_str("Nobody <noreply@somewhere.com>")
                .expect("Valid email")
                .into(),
        }
    }
}

impl MailConfig {
    pub fn new(from: Mailboxes) -> MailConfig {
        let mut config = Self::default();
        config.from = from;
        config
    }

    pub fn from_string(s: String) -> anyhow::Result<Self> {
        MailConfig::from_str(s.as_str())
    }
}

impl FromStr for MailConfig {
    type Err = anyhow::Error;

    fn from_str(from: &str) -> Result<Self, Self::Err> {
        let from = Mailbox::from_str(from)?;
        Ok(MailConfig::new(from.into()))
    }
}

impl MailConfig {
    pub fn reply_to(&self) -> &Mailboxes {
        &self.reply_to
    }

    pub fn from(&self) -> &Mailboxes {
        &self.from
    }

    #[must_use]
    pub fn create(
        &self,
        to: Mailboxes,
        subject: &str,
        message_id: Option<String>,
        content_type: Option<ContentType>,
    ) -> MessageBuilder {
        let mut message = Message::builder().subject(subject).message_id(message_id);
        if let Some(content_type) = content_type {
            // do not put multipart message as text/plain
            message = message.header(content_type)
        }
        for t in to {
            message = message.to(t);
        }
        for r in self.reply_to.iter() {
            message = message.reply_to(r.clone());
        }
        for f in self.from.iter() {
            message = message.from(f.clone());
        }
        message
    }

    pub fn create_mail<B: IntoBody>(
        &self,
        html: bool,
        to: Mailboxes,
        subject: &str,
        message_id: Option<String>,
        body: B,
    ) -> anyhow::Result<Message> {
        Ok(self
            .create(
                to,
                subject,
                message_id,
                if html {
                    Some(ContentType::TEXT_HTML)
                } else {
                    Some(ContentType::TEXT_PLAIN)
                },
            )
            .body(body)?)
    }

    pub fn create_mail_multipart(
        &self,
        to: Mailboxes,
        subject: &str,
        message_id: Option<String>,
        part: MultiPart,
    ) -> anyhow::Result<Message> {
        Ok(self.create(to, subject, message_id, None).multipart(part)?)
    }
}
