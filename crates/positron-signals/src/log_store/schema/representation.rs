/// Physical placement selected for one valid attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaRepresentation {
    Cataloged,
    Overflow,
}

impl SchemaRepresentation {
    #[must_use]
    pub const fn is_cataloged(self) -> bool {
        matches!(self, Self::Cataloged)
    }

    #[must_use]
    pub const fn is_overflow(self) -> bool {
        matches!(self, Self::Overflow)
    }
}
