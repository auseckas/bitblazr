use thiserror::Error;

#[derive(Error, Debug)]
pub enum BSError<'a> {
    #[error("Invalid attribute type: {attribute:?}, type: {value:?}")]
    InvalidAttributeType { attribute: &'a str, value: String },
    #[error("Invalid attribute: {attribute:?}, value: {value:?}")]
    InvalidAttribute { attribute: &'a str, value: String },
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Deserialize error: {0}")]
    Deserialize(String),
}
