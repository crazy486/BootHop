use boothop_core::BootId;

const MARKER_SCHEMA: &str = "BOOTHOP_ARCH_V1";
const MARKER_PATH: &str = "EFI/BootHop/arch.efi";
pub const IDENTITY_MARKER_PATH: &str = "/var/lib/boothop/arch-direct.identity";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    InvalidMarker,
}

/// The one installed identity accepted by the Arch UKI post hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledIdentity {
    boot_id: BootId,
    option_sha256: [u8; 32],
}

impl InstalledIdentity {
    pub fn new(boot_id: BootId, option_sha256: [u8; 32]) -> Result<Self, IdentityError> {
        if boot_id.0 == 0 {
            return Err(IdentityError::InvalidMarker);
        }
        Ok(Self {
            boot_id,
            option_sha256,
        })
    }

    pub fn boot_id(&self) -> BootId {
        self.boot_id
    }

    pub fn option_sha256(&self) -> [u8; 32] {
        self.option_sha256
    }

    /// Encode the exact four-line marker stored at `/var/lib/boothop/arch-direct.identity`.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(15 + 13 + 64 + 29 + 4);
        bytes.extend_from_slice(MARKER_SCHEMA.as_bytes());
        bytes.extend_from_slice(b"\nboot_id=");
        bytes.extend_from_slice(format!("{:04X}", self.boot_id.0).as_bytes());
        bytes.extend_from_slice(b"\noption_sha256=");
        for byte in self.option_sha256 {
            bytes.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        bytes.extend_from_slice(b"\npath=");
        bytes.extend_from_slice(MARKER_PATH.as_bytes());
        bytes.push(b'\n');
        bytes
    }

    /// Parse only the supported schema and its canonical byte representation.
    pub fn parse(bytes: &[u8]) -> Result<Self, IdentityError> {
        let text = std::str::from_utf8(bytes).map_err(|_| IdentityError::InvalidMarker)?;
        let content = text
            .strip_suffix('\n')
            .ok_or(IdentityError::InvalidMarker)?;
        let lines = content.split('\n').collect::<Vec<_>>();
        if lines.len() != 4 || lines[0] != MARKER_SCHEMA || lines[3] != "path=EFI/BootHop/arch.efi"
        {
            return Err(IdentityError::InvalidMarker);
        }

        let boot_id = lines[1]
            .strip_prefix("boot_id=")
            .filter(|value| value.len() == 4)
            .ok_or(IdentityError::InvalidMarker)?;
        let boot_id = parse_upper_hex_u16(boot_id).ok_or(IdentityError::InvalidMarker)?;
        if boot_id == 0 {
            return Err(IdentityError::InvalidMarker);
        }

        let digest = lines[2]
            .strip_prefix("option_sha256=")
            .filter(|value| value.len() == 64)
            .ok_or(IdentityError::InvalidMarker)?;
        let mut option_sha256 = [0_u8; 32];
        for (index, pair) in digest.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = lower_hex_nibble(pair[0]).ok_or(IdentityError::InvalidMarker)?;
            let low = lower_hex_nibble(pair[1]).ok_or(IdentityError::InvalidMarker)?;
            option_sha256[index] = (high << 4) | low;
        }

        let identity = Self::new(BootId(boot_id), option_sha256)?;
        if identity.encode() != bytes {
            return Err(IdentityError::InvalidMarker);
        }
        Ok(identity)
    }
}

fn parse_upper_hex_u16(value: &str) -> Option<u16> {
    let mut parsed = 0_u16;
    for byte in value.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        parsed = parsed.checked_mul(16)?.checked_add(u16::from(nibble))?;
    }
    Some(parsed)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
