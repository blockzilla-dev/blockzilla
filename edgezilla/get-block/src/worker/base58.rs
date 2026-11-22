//! Variable-length Bitcoin Base58. Each limb holds five output digits and each
//! multiply/add step consumes four input bytes. Fixed 32/64-byte values still
//! use five8 in the parent module.

const RADIX: u64 = 656_356_768; // 58^5
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub(super) fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let significant = &bytes[zeros..];
    if significant.is_empty() {
        return "1".repeat(zeros);
    }
    let mut limbs = Vec::<u32>::with_capacity(significant.len().saturating_mul(138) / 500 + 1);
    let first_len = match significant.len() % 4 {
        0 => 4,
        length => length,
    };
    let mut first = 0u32;
    for byte in &significant[..first_len] {
        first = (first << 8) | u32::from(*byte);
    }
    let mut carry = u64::from(first);
    while carry != 0 {
        limbs.push((carry % RADIX) as u32);
        carry /= RADIX;
    }
    for word in significant[first_len..].chunks_exact(4) {
        let mut carry = u64::from(u32::from_be_bytes(word.try_into().expect("four-byte word")));
        for limb in &mut limbs {
            // limb < 58^5 and carry < 2^32. The sum is below 58^5 * 2^32,
            // so it fits u64. Both division operands have a fixed radix.
            let value = (u64::from(*limb) << 32) + carry;
            *limb = (value % RADIX) as u32;
            carry = value / RADIX;
        }
        while carry != 0 {
            limbs.push((carry % RADIX) as u32);
            carry /= RADIX;
        }
    }
    let mut output = Vec::with_capacity(zeros.saturating_add(limbs.len().saturating_mul(5)));
    output.resize(zeros, b'1');
    let mut first = true;
    for mut limb in limbs.into_iter().rev() {
        let mut digits = [b'1'; 5];
        for digit in digits.iter_mut().rev() {
            *digit = ALPHABET[(limb % 58) as usize];
            limb /= 58;
        }
        if first {
            let start = digits
                .iter()
                .position(|digit| *digit != b'1')
                .expect("nonzero top limb");
            output.extend_from_slice(&digits[start..]);
            first = false;
        } else {
            output.extend_from_slice(&digits);
        }
    }
    String::from_utf8(output).expect("Base58 alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_for_group_boundaries_and_zero_prefixes() {
        for length in [
            0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
            1024, 4096,
        ] {
            for zeros in [0, 1, 3, 5, 16] {
                let mut bytes = vec![0; zeros];
                bytes.extend((0..length).map(|index| ((index * 73 + 157) % 256) as u8));
                assert_eq!(
                    encode(&bytes),
                    bs58::encode(&bytes).into_string(),
                    "length={length} zeros={zeros}"
                );
            }
            let zeros = vec![0; length];
            assert_eq!(encode(&zeros), bs58::encode(&zeros).into_string());
            let largest = vec![255; length];
            assert_eq!(encode(&largest), bs58::encode(&largest).into_string());
        }
    }

    #[test]
    fn matches_reference_for_deterministic_random_words_and_leading_digits() {
        let mut random = 0x83ab_f019_29d4_c807u64;
        for length in 0..=4096 {
            let bytes = (0..length)
                .map(|_| {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    random as u8
                })
                .collect::<Vec<_>>();
            assert_eq!(
                encode(&bytes),
                bs58::encode(&bytes).into_string(),
                "length={length}"
            );
        }
        for value in [
            1u64,
            57,
            58,
            59,
            RADIX - 1,
            RADIX,
            RADIX + 1,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let bytes = value.to_be_bytes();
            assert_eq!(encode(&bytes), bs58::encode(bytes).into_string());
        }
    }
}
