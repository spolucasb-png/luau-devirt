//! Source-proved initOnce -> initB -> initC arithmetic and data dependencies.
use super::{read32, SALT, TRANSPORT_BYTES};

#[derive(Clone, Debug)]
pub struct Initialization {
    pub header: [u32; 4],
    pub master_key: u32,
    pub float_bits: u64,
    pub zero_counts: u32,
    pub range: (usize, usize),
    pub permutation_a: Vec<u16>,
    pub permutation_b: Vec<u16>,
    pub permutation_c: Vec<u16>,
}

fn stream(value: u32) -> u32 {
    // initOnce, both header and range loops: the same state is continued.
    let mut value = value
        .wrapping_mul(411395)
        .wrapping_add(479499883)
        .rotate_left(11);
    value ^= value << 9;
    value ^= value >> 5;
    value ^= value << 1;
    value
}

pub(super) fn permutations() -> (Vec<u16>, Vec<u16>, Vec<u16>) {
    let mut a = (0..16384u16).collect::<Vec<_>>();
    let mut b = a.clone();
    let mut c = vec![0; 16384];
    let (mut ka, mut kb) = (1074033615u32, 2285263105u32);
    for index in (1..16384usize).rev() {
        ka = ka.wrapping_mul(29983).wrapping_add(3162639897);
        a.swap(index, (ka % (index as u32 + 1)) as usize);
        kb = kb.wrapping_mul(29983).wrapping_add(3162639897);
        b.swap(index, (kb % (index as u32 + 1)) as usize);
    }
    for index in 0..16384 {
        let (pa, pb) = (a[index] as u32, b[index] as u32);
        c[pa as usize] = ((pb * 4
            + ((index as u32 * 17 + 13025) % 16384) * 2
            + (((pa >> 7) & 1) ^ ((pb >> 2) & 1) ^ 1)
            + SALT)
            % 65536) as u16;
    }
    for index in 0..16384 {
        ka = ka.wrapping_mul(29983).wrapping_add(3162639897);
        kb = kb.wrapping_mul(29983).wrapping_add(3162639897);
        a[index] |= (((ka >> 20) & 3) << 14) as u16;
        b[index] |= (((kb >> 20) & 3) << 14) as u16;
    }
    (a, b, c)
}

/// Static cipher arithmetic only. Source certification is performed before
/// calling this in production; it is also exposed for independent diagnostics.
pub fn initialize_data(
    payload: &[u8],
    argument: u32,
) -> Result<(Vec<Option<u32>>, Vec<u16>, Vec<u32>, Initialization), String> {
    if payload.len() != TRANSPORT_BYTES {
        return Err(
            "large SARP initialization requires the certified 568176-byte buffer".to_owned(),
        );
    }
    let count = payload.len() / 4;
    let mut words = vec![None; count + 1];
    let mut state = argument ^ 192128608;
    let mut header = [0; 4];
    for index in 1..=4 {
        state = stream(state);
        header[index - 1] = read32(payload, (index - 1) * 4)? ^ state;
        words[index] = Some(header[index - 1]);
    }
    let bw = read32(payload, 8)?;
    let m0 = argument ^ bw;
    let m1 = m0.wrapping_mul(29955).wrapping_add(504689345);
    let float_bits = (m1 as f64 + header[2] as f64 + 1048576.0).to_bits();
    let (lo, hi) = (float_bits as u32, (float_bits >> 32) as u32);
    let zero_counts =
        m0.leading_zeros() * 65537 + bw.trailing_zeros() * 257 + header[2].leading_zeros();
    // The wrapper's plain-table addition fails pcall/xpcall; the error handler
    // returns 6099 and sets 15. Its literal metamethod calculations and two
    // coroutine resumes are total. Array/pack/format/math/clone checks are
    // certified library identities, yielding _pf = 0 and _pe = 0. No functions
    // or coroutines are invoked here.
    let master_key =
        m1.wrapping_add(lo) ^ header[2].rotate_left(11) ^ hi ^ m0.swap_bytes() ^ zero_counts;
    let low = (header[1] ^ 2659961469 ^ master_key) as usize;
    let high = (header[3] ^ 4067770469 ^ master_key) as usize;
    if low < 5 || low > high || high.checked_add(867).is_none_or(|n| n > count) {
        return Err(format!("large SARP header bounds invalid: {low}..={high}"));
    }
    for index in low..=high {
        state = stream(state);
        words[index] = Some(read32(payload, (index - 1) * 4)? ^ state);
    }
    let mut biases = vec![0];
    let mut key = 299753647u32;
    for _ in 0..64 {
        key = key.wrapping_mul(13003).wrapping_add(3750079167);
        biases.push(1 + key % 200000);
    }
    let (a, b, c) = permutations();
    let mut key = master_key ^ 1836873615;
    for index in low..=high {
        key = key.wrapping_mul(32625).wrapping_add(2288117495);
        let mask = a[(key & 16383) as usize] as u32
            ^ ((b[((key >> 14) & 16383) as usize] as u32) << 16)
            ^ biases[1 + index % 64]
            ^ c[((key ^ index as u32) & 16383) as usize] as u32;
        words[index] = Some(words[index].ok_or("missing first-layer word")? ^ mask);
    }
    // initC reads register-map words from raw B, not transformed W.
    let mut slots = vec![0];
    let mut key = 3662345728 ^ master_key;
    for index in 0..867 {
        key = key.wrapping_mul(16973).wrapping_add(1663117091);
        let value = read32(payload, high * 4 + index * 4)? ^ key;
        slots.extend([value as u16, (value >> 16) as u16]);
    }
    if slots.iter().skip(1).any(|s| *s == 0 || *s > 71) {
        return Err(
            "large SARP register map contains a corrupt/unsupported physical slot".to_owned(),
        );
    }
    let init = Initialization {
        header,
        master_key,
        float_bits,
        zero_counts,
        range: (low, high),
        permutation_a: a,
        permutation_b: b,
        permutation_c: c,
    };
    Ok((words, slots, biases, init))
}
