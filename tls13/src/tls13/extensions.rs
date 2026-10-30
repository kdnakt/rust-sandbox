use crate::tls13::common::*;

pub struct Extension {
    pub extension_type: ExtensionType,
    pub payload: Vec<u8>,
}
