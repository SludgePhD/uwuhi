/// ffi_enum! {}
macro_rules! ffi_enum {
    (
        $( #[$attrs:meta] )*
        $v:vis enum $name:ident: $native:ty {
            $(
                $( #[$variant_attrs:meta] )*
                $variant:ident = $value:expr
            ),+
            $(,)?
        }
    ) => {
        $( #[$attrs] )*
        #[derive(Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
        #[repr(transparent)]
        $v struct $name(pub(crate) $native);

        impl $name {
            $(
                $( #[$variant_attrs] )*
                $v const $variant: Self = Self($value);
            )+
        }

        #[allow(unreachable_patterns)]
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    $(
                        Self::$variant => f.write_str(stringify!($variant)),
                    )+

                    _ => write!(f, "(unknown {}: {:#x})", stringify!($name), self.0),
                }
            }
        }
    };
}
