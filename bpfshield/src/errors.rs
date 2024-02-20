use thiserror::Error;

#[derive(Error, Debug)]
pub enum BSError<'a> {
    #[error("Invalid attribute: {attribute:?}, value: {value:?}")]
    InvalidAttribute { attribute: &'a str, value: String },
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
}
