use crate::device_path::first_path_length;
use crate::{Error, LoadOption, parse_device_path};

const MAX_LOAD_OPTION_BYTES: usize = 1_048_576;
const LOAD_OPTION_HEADER_BYTES: usize = 6;

pub fn parse_load_option(bytes: &[u8]) -> Result<LoadOption, Error> {
    if bytes.len() > MAX_LOAD_OPTION_BYTES {
        return Err(Error::ResourceLimit);
    }

    let header = bytes
        .get(..LOAD_OPTION_HEADER_BYTES)
        .ok_or(Error::MalformedLoadOption)?;
    let attributes = read_u32(header, 0)?;
    let file_path_list_length = read_u16(header, 4)?;

    let mut description_utf16 = Vec::new();
    let mut offset = LOAD_OPTION_HEADER_BYTES;
    loop {
        let unit_end = offset.checked_add(2).ok_or(Error::MalformedLoadOption)?;
        let unit = read_u16(bytes, offset)?;
        offset = unit_end;
        if unit == 0 {
            break;
        }
        description_utf16.push(unit);
    }
    if !valid_utf16(&description_utf16) {
        return Err(Error::MalformedLoadOption);
    }

    let file_path_end = offset
        .checked_add(usize::from(file_path_list_length))
        .ok_or(Error::MalformedLoadOption)?;
    let file_path_bytes = bytes
        .get(offset..file_path_end)
        .ok_or(Error::MalformedLoadOption)?;
    let optional_data = bytes
        .get(file_path_end..)
        .ok_or(Error::MalformedLoadOption)?
        .to_vec();

    let mut file_paths = Vec::new();
    let mut path_offset = 0_usize;
    while path_offset < file_path_bytes.len() {
        let remaining = file_path_bytes
            .get(path_offset..)
            .ok_or(Error::MalformedDevicePath)?;
        let path_length = first_path_length(remaining)?;
        let path_end = path_offset
            .checked_add(path_length)
            .ok_or(Error::MalformedDevicePath)?;
        let path_bytes = file_path_bytes
            .get(path_offset..path_end)
            .ok_or(Error::MalformedDevicePath)?;
        file_paths.push(parse_device_path(path_bytes)?);
        path_offset = path_end;
    }

    Ok(LoadOption {
        attributes,
        description_utf16,
        file_path_list_length,
        file_paths,
        optional_data,
    })
}

fn valid_utf16(code_units: &[u16]) -> bool {
    char::decode_utf16(code_units.iter().copied()).all(|decoded| decoded.is_ok())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::MalformedLoadOption)?;
    let pair: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedLoadOption)?
        .try_into()
        .map_err(|_| Error::MalformedLoadOption)?;
    Ok(u16::from_le_bytes(pair))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::MalformedLoadOption)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::MalformedLoadOption)?
        .try_into()
        .map_err(|_| Error::MalformedLoadOption)?;
    Ok(u32::from_le_bytes(value))
}
