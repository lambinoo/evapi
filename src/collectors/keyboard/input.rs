use std::ptr::null_mut;

use winapi::{
    shared::minwindef::HKL,
    um::{
        processthreadsapi::GetCurrentThreadId,
        winuser::{
            AttachThreadInput, GetForegroundWindow, GetKeyboardLayout, GetKeyboardState,
            GetWindowThreadProcessId, MapVirtualKeyA, ToUnicodeEx, MAPVK_VK_TO_VSC,
        },
    },
};

use super::hook::MODIFIER_STATE;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyAction {
    Up,
    Down,
    Unknown,
    IgnoreThis,
}

#[derive(Clone, Debug)]
pub struct KeyboardInput {
    pub scan_code: u32,
    pub vk_code: u32,
    pub unicode: Option<Unicode>,
    pub action: KeyAction,
}

impl KeyboardInput {
    pub fn is_up(&self) -> bool {
        self.action == KeyAction::Up
    }

    pub fn is_down(&self) -> bool {
        self.action == KeyAction::Down
    }

    pub fn as_str(&self) -> &str {
        self.unicode
            .as_ref()
            .map(|unicode| match unicode {
                Unicode::Character(s) => s.as_str(),
                Unicode::DeadKey(s) => s.as_str(),
                Unicode::Empty => "",
            })
            .unwrap_or("")
    }

    pub fn to_unicode(scan_code: u32, vk_code: u32) -> Option<Unicode> {
        let mut keyboard_state = [0; 256];
        let mut value = [0; 9];

        if Self::get_keyboard_state(&mut keyboard_state) {
            let return_code = unsafe {
                ToUnicodeEx(
                    vk_code,
                    scan_code,
                    keyboard_state.as_ptr(),
                    value.as_mut_ptr(),
                    8,
                    1 << 2,
                    KeyboardInput::get_active_layout(),
                )
            };

            match return_code {
                -1 => String::from_utf16(&value[0..1])
                    .ok()
                    .map(|s| Unicode::DeadKey(s.replace('\x00', ""))),
                0 => Some(Unicode::Empty),
                n if n > 0 => String::from_utf16(&value)
                    .ok()
                    .map(|s| Unicode::Character(s.replace('\x00', ""))),
                _ => None,
            }
        } else {
            None
        }
    }

    fn get_keyboard_state(keyboard_state: &mut [u8; 256]) -> bool {
        let foreground_window = unsafe { GetForegroundWindow() };
        let foreground_thread = unsafe { GetWindowThreadProcessId(foreground_window, null_mut()) };
        let current_thread = unsafe { GetCurrentThreadId() };

        let attach_return_code =
            unsafe { AttachThreadInput(current_thread, foreground_thread, true as _) };
        unsafe {
            if attach_return_code != 0 {
                let success = GetKeyboardState(keyboard_state.as_mut_ptr()) != 0;
                AttachThreadInput(current_thread, foreground_thread, false as _);
                MODIFIER_STATE.set_keyboard_state(keyboard_state);
                success
            } else {
                GetKeyboardState(keyboard_state.as_mut_ptr()) != 0
            }
        }
    }

    fn get_active_layout() -> HKL {
        unsafe { GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), &mut 0)) }
    }
}

impl Default for KeyboardInput {
    fn default() -> Self {
        KeyboardInput {
            scan_code: 0,
            vk_code: 0,
            unicode: None,
            action: KeyAction::IgnoreThis,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Unicode {
    DeadKey(String),
    Character(String),
    Empty,
}
