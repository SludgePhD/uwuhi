#[derive(Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub(crate) struct U16(u16);

impl U16 {
    pub(crate) fn get(self) -> u16 {
        u16::from_be(self.0)
    }
}

impl From<u16> for U16 {
    fn from(value: u16) -> Self {
        Self(value.to_be())
    }
}

#[derive(Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub(crate) struct U32(u32);

impl U32 {
    pub(crate) fn get(self) -> u32 {
        u32::from_be(self.0)
    }
}

impl From<u32> for U32 {
    fn from(value: u32) -> Self {
        Self(value.to_be())
    }
}
