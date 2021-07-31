use std::{fmt::write, ptr::null_mut, slice::from_raw_parts};

use base64::encode;
use png::{BitDepth, ColorType};
use winapi::um::wingdi::{BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateDCA, DeleteDC, GetDeviceCaps, HORZRES, SRCCOPY, SelectObject, VERTRES};

pub fn take_screenshot() -> Option<Vec<u8>> {
/*    unsafe {
        let screen_dc = unsafe {  CreateDCA("DISPLAY".as_bytes().as_ptr() as *const _, null_mut(), null_mut(), null_mut()) };
        let memory_dc = unsafe { CreateCompatibleDC(screen_dc) };

        let width = unsafe { GetDeviceCaps(screen_dc, HORZRES) };
        let height = unsafe { GetDeviceCaps(screen_dc, VERTRES) };

        let bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        let hold_bitmap = SelectObject(memory_dc, bitmap);

        BitBlt(memory_dc, 0, 0, width, height, screen_dc, 0, 0, SRCCOPY);
        let bitmap = SelectObject(memory_dc, hold_bitmap);

        DeleteDC(memory_dc);
        DeleteDC(screen_dc);

        let mut end_buffer = Vec::new();
        let encoder = png::Encoder::new(&mut end_buffer, width as _, height as _);
        encoder.set_depth(BitDepth::Sixteen);
        encoder.set_color(ColorType::RGB);

        let mut png_encoder = encoder.write_header().ok()?;
    }*/

    todo!()
}