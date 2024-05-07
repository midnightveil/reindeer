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

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn works_smaller_type() {
        let range = Range::<u32> {
            start: kani::any(),
            end: kani::any(),
        };

        assert!(range.try_into_usize().is_ok());
    }

    #[kani::proof]
    fn works_larger_type() {
        let range = Range::<u128> {
            start: kani::any(),
            end: kani::any(),
        };

        kani::assume(range.start <= usize::MAX as u128);
        kani::assume(range.end <= usize::MAX as u128);

        assert!(range.try_into_usize().is_ok());
    }

    #[kani::proof]
    fn safely_handles_larger_type_oob() {
        let range = Range::<u128> {
            start: kani::any(),
            end: kani::any(),
        };

        kani::assume(range.start > usize::MAX as u128 || range.end > usize::MAX as u128);

        assert!(range.try_into_usize().is_err());
    }
}
