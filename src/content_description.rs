use lettre::message::header::{Header, HeaderName, HeaderValue};

/// `Content-Description` of an attachment
///
/// Defined in [RFC2045](https://tools.ietf.org/html/rfc2045#section-8)
#[derive(Debug, Clone, PartialEq)]
pub struct ContentDescription(HeaderValue);

impl Header for ContentDescription {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-Description")
    }

    fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self(HeaderValue::new(Self::name(), s.to_string())))
    }

    fn display(&self) -> HeaderValue {
        self.0.clone()
    }
}
