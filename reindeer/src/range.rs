use core::ops::Range;

/// Convert a `Range<T>` into `Range<usize>` via TryInto-like trait.
pub trait TryIntoRangeUsize: Sized {
    type Error;
    /// Convert to `Range<usize>`.
    fn try_into_usize(self) -> Result<Range<usize>, Self::Error>;
}

impl<T: TryInto<usize>> TryIntoRangeUsize for Range<T> {
    type Error = T::Error;

    fn try_into_usize(self) -> Result<Range<usize>, Self::Error> {
        Ok(Range {
            start: self.start.try_into()?,
            end: self.end.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works_smaller_type() {
        let range = Range {
            start: 0u32,
            end: 10u32,
        };

        assert!(range.try_into_usize().is_ok());
    }

    #[test]
    fn works_larger_type() {
        let range = Range {
            start: 0u128,
            end: 10u128,
        };
        assert!(range.try_into_usize().is_ok());
    }

    #[test]
    fn safely_handles_larger_type_oob() {
        let range = Range {
            start: u128::MAX - 10,
            end: u128::MAX,
        };
        assert!(range.try_into_usize().is_err());
    }
}
