//! Bound a slot lookup using only the counts of sorted, unique archive rows.
//!
//! Every row occupies one slot in the admitted range. Before slot offset `d`,
//! at most `slot_count - row_count` slots can have no row. Thus a row for `d`
//! can only have an ordinal from `d - missing` through `d`, clipped to the row
//! range. Absence from this window does not establish a skipped chain slot.

use std::ops::Range;

pub(crate) fn ordinal_window(
    first_slot: u64,
    slot_count: u64,
    row_count: u64,
    slot: u64,
) -> Result<Range<u64>, String> {
    if slot_count == 0 {
        return Err("slot lookup range must contain at least one slot".into());
    }
    if row_count > slot_count {
        return Err("slot lookup row count exceeds the slot count".into());
    }
    first_slot
        .checked_add(slot_count - 1)
        .ok_or_else(|| "slot lookup range overflows u64".to_string())?;
    let offset = slot
        .checked_sub(first_slot)
        .filter(|offset| *offset < slot_count)
        .ok_or_else(|| "requested slot is outside the slot lookup range".to_string())?;
    let missing = slot_count - row_count;
    // offset < slot_count <= u64::MAX, so offset + 1 cannot overflow.
    Ok(offset.saturating_sub(missing)..(offset + 1).min(row_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_present_ordinal_is_inside_its_window_for_every_eight_slot_subset() {
        const FIRST: u64 = 100;
        const COUNT: u64 = 8;
        for mask in 0u16..(1 << COUNT) {
            let slots = (0..COUNT)
                .filter(|offset| mask & (1 << offset) != 0)
                .map(|offset| FIRST + offset)
                .collect::<Vec<_>>();
            for (ordinal, slot) in slots.iter().enumerate() {
                let window = ordinal_window(FIRST, COUNT, slots.len() as u64, *slot).unwrap();
                assert!(!window.is_empty(), "mask={mask}, slot={slot}");
                assert!(
                    window.contains(&(ordinal as u64)),
                    "mask={mask}, slot={slot}, ordinal={ordinal}, window={window:?}"
                );
                assert!(window.end <= slots.len() as u64);
            }
        }
    }

    #[test]
    fn full_range_selects_one_ordinal_and_near_full_range_stays_small() {
        for slot in 10..18 {
            assert_eq!(ordinal_window(10, 8, 8, slot).unwrap(), slot - 10..slot - 9);
        }
        assert_eq!(
            ordinal_window(0, 432_000, 431_900, 200_000).unwrap(),
            199_900..200_001
        );
        assert_eq!(ordinal_window(0, 432_000, 431_900, 0).unwrap(), 0..1);
        assert_eq!(
            ordinal_window(0, 432_000, 431_900, 431_999).unwrap(),
            431_899..431_900
        );
    }

    #[test]
    fn zero_rows_have_empty_windows_at_every_slot() {
        for slot in 100..108 {
            assert_eq!(ordinal_window(100, 8, 0, slot).unwrap(), 0..0);
        }
    }

    #[test]
    fn rejects_invalid_counts_slots_and_overflow() {
        assert!(ordinal_window(100, 0, 0, 100).is_err());
        assert!(ordinal_window(100, 8, 9, 100).is_err());
        assert!(ordinal_window(100, 8, 8, 99).is_err());
        assert!(ordinal_window(100, 8, 8, 108).is_err());
        assert!(ordinal_window(u64::MAX, 2, 1, u64::MAX).is_err());
        assert_eq!(ordinal_window(u64::MAX, 1, 1, u64::MAX).unwrap(), 0..1);
        assert_eq!(
            ordinal_window(1, u64::MAX, u64::MAX, u64::MAX).unwrap(),
            u64::MAX - 1..u64::MAX
        );
        assert!(ordinal_window(0, u64::MAX, u64::MAX, u64::MAX).is_err());
    }
}
