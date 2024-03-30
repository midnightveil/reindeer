use std::ops::Range;

/// Convert a Range<T> into Range<usize> via TryInto trait.
///
/// # Examples
///
/// ```
/// use std::ops::Range;
/// use reindeerlib::range::as_range_usize;
///
/// let range = Range { start: 0u64, end: 10u64 };
/// assert_eq!(as_range_usize(range).unwrap(), Range { start: 0usize, end: 10usize });
/// ```
pub fn as_range_usize<T: TryInto<usize>>(range: Range<T>) -> Result<Range<usize>, T::Error> {
    Ok(Range {
        start: range.start.try_into()?,
        end: range.end.try_into()?,
    })
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

        assert!(as_range_usize(range).is_ok());
    }

    #[test]
    fn works_larger_type() {
        let range = Range {
            start: 0u128,
            end: 10u128,
        };
        assert!(as_range_usize(range).is_ok());
    }

    #[test]
    fn safely_handles_larger_type_oob() {
        let range = Range {
            start: u128::MAX - 10,
            end: u128::MAX,
        };
        assert!(as_range_usize(range).is_err());
    }
}
