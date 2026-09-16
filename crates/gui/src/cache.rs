use boothop_core::{BootId, Os};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedTarget {
    pub boot_id: BootId,
    pub os: Os,
    pub description_utf16: Option<Vec<u16>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheError {
    Unavailable,
}
pub trait Cache {
    fn load(&self) -> Result<Option<CachedTarget>, CacheError>;
    fn save(&self, target: &CachedTarget) -> Result<(), CacheError>;
}

/// One bounded line. Invalid UTF-16, controls and directional formatting cannot forge UI labels.
pub fn safe_description(units: &[u16]) -> String {
    let mut display = String::new();
    for value in char::decode_utf16(units.iter().copied()) {
        let ch = value.unwrap_or(char::REPLACEMENT_CHARACTER);
        let ch = if ch.is_control()
            || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            char::REPLACEMENT_CHARACTER
        } else {
            ch
        };
        if display.len() + ch.len_utf8() > 2048 {
            break;
        }
        display.push(ch);
    }
    display
}

/// Canonicalize untrusted UTF-16 before it is persisted as UI state. The
/// resulting value contains only bounded, display-safe Unicode scalar values.
pub(crate) fn sanitized_description(units: &[u16]) -> Vec<u16> {
    safe_description(units).encode_utf16().collect()
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxCache, resolve_cache_path};

mod windows;
pub use windows::{WindowsCache, resolve_windows_cache_path};
