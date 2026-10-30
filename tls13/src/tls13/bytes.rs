
pub fn with_u16length(body: &Vec<u8>) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&((body.len() as u16).to_be_bytes()));
    result.extend_from_slice(body);
    result
}
