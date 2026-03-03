/// Raw structure representing a lightweight ETW event payload
/// before being normalized into a SharedEvent.
///
/// In a real system, this might contain pointers to raw unparsed memory or UTF-16 buffers.
#[derive(Debug)]
pub struct RawEvent<'a> {
    pub provider_id: &'a str,
    pub event_id: u16,
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    // Keeps string as borrowed to prevent allocation until necessary
    pub raw_image_path: &'a str,
    pub command_line: Option<&'a str>,
}
