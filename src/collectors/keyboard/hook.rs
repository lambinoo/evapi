use super::input::*;
use std::convert::TryFrom;
use std::{
    ptr::{null_mut, NonNull},
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;
use winapi::{
    ctypes::c_int,
    shared::minwindef::{LPARAM, LRESULT, WPARAM},
    um::winuser::{
        CallNextHookEx, MapVirtualKeyA, KBDLLHOOKSTRUCT, MAPVK_VK_TO_CHAR, VK_CONTROL, VK_LCONTROL,
        VK_LMENU, VK_LSHIFT, VK_MENU, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_SHIFT, WM_KEYDOWN,
        WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
    },
};

lazy_static! {
    pub static ref KL_CHANNEL: (watch::Sender<KeyboardInput>, watch::Receiver<KeyboardInput>) =
        watch::channel(KeyboardInput::default());
}

pub static MODIFIER_STATE: ModifierState = ModifierState {
    shift: AtomicBool::new(false),
    menu: AtomicBool::new(false),
    ctrl: AtomicBool::new(false),
};

#[derive(Debug)]
pub struct ModifierState {
    shift: AtomicBool,
    menu: AtomicBool,
    ctrl: AtomicBool,
}

impl ModifierState {
    pub fn reset(&self) {
        self.shift.store(false, Ordering::Relaxed);
        self.menu.store(false, Ordering::Relaxed);
        self.ctrl.store(false, Ordering::Relaxed);
    }

    pub fn set_keyboard_state(&self, keyboard_state: &mut [u8; 256]) {
        keyboard_state[VK_SHIFT as usize] = Self::bool_to_state(&self.shift);
        keyboard_state[VK_MENU as usize] = Self::bool_to_state(&self.menu);
        keyboard_state[VK_CONTROL as usize] = Self::bool_to_state(&self.ctrl);
    }

    fn bool_to_state(value: &AtomicBool) -> u8 {
        if value.load(Ordering::Relaxed) {
            0x80
        } else {
            0
        }
    }
}

fn is_dead_key(vk_code: u32) -> bool {
    unsafe {
        let char_value = MapVirtualKeyA(vk_code, MAPVK_VK_TO_CHAR);
        (char_value & 1 << 31) != 0
    }
}

pub extern "system" fn keyboard_hook(code: c_int, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    #[inline]
    fn is_down(event_type: u32) -> bool {
        event_type == WM_KEYDOWN || event_type == WM_SYSKEYDOWN
    }

    #[inline]
    fn set_keyboard_modifier_state(vk_code: u32, event_type: u32) {
        match vk_code as i32 {
            VK_SHIFT | VK_LSHIFT | VK_RSHIFT => MODIFIER_STATE
                .shift
                .store(is_down(event_type), Ordering::Relaxed),
            VK_CONTROL | VK_LCONTROL | VK_RCONTROL => MODIFIER_STATE
                .ctrl
                .store(is_down(event_type), Ordering::Relaxed),
            VK_MENU | VK_LMENU | VK_RMENU => MODIFIER_STATE
                .menu
                .store(is_down(event_type), Ordering::Relaxed),
            _ => {}
        }
    }

    if code >= 0 {
        if let Some(keyboard) = NonNull::new(lparam as *mut KBDLLHOOKSTRUCT) {
            let event_type = u32::try_from(wparam).unwrap();
            let keyboard = unsafe { keyboard.as_ref() };

            if !is_dead_key(keyboard.vkCode) {
                let action = match event_type {
                    WM_KEYUP | WM_SYSKEYUP => KeyAction::Up,
                    WM_KEYDOWN | WM_SYSKEYDOWN => KeyAction::Down,
                    _ => KeyAction::Unknown,
                };

                set_keyboard_modifier_state(keyboard.vkCode, event_type);

                let input = KeyboardInput {
                    scan_code: keyboard.scanCode,
                    vk_code: keyboard.vkCode,
                    unicode: KeyboardInput::to_unicode(keyboard.scanCode, keyboard.vkCode),
                    action,
                };
                let _ = KL_CHANNEL.0.broadcast(input);
            }
        }
    }

    unsafe { CallNextHookEx(null_mut(), code, wparam, lparam) }
}
