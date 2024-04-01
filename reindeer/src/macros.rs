macro_rules! enum_getter {
    ($property:ident, Option<$typ:ty>) => {
        #[inline]
        pub fn $property(&self) -> Option<$typ> {
            match self {
                Self::Elf32(header) => header.$property.map(Into::into),
                Self::Elf64(header) => header.$property,
            }
        }
    };
    (&$property:ident, $type:ty) => {
        #[inline]
        pub fn $property(&self) -> $type {
            match self {
                Self::Elf32(header) => &header.$property,
                Self::Elf64(header) => &header.$property,
            }
        }
    };
    ($property:ident, $type:ty) => {
        #[inline]
        pub fn $property(&self) -> $type {
            match self {
                Self::Elf32(header) => header.$property.into(),
                Self::Elf64(header) => header.$property,
            }
        }
    };
}

macro_rules! declare_constants {
    ($typ:ty, {$($name:ident = $value:literal),* $(,)?}) => {
        impl $typ {
            $(
                pub const $name: Self = Self($value);
            )*

            pub fn name(self) -> Cow<'static, str> {
                match self {
                    $(
                        Self::$name => stringify!($name).into(),
                    )*
                    Self(value) => format!("{:#x}", value).into(),
                }
            }
        }
    };
}

pub(crate) use declare_constants;
pub(crate) use enum_getter;
