pub fn add(left: usize, right: usize) -> usize {
    left + right
}

const STATE_LEN: usize = 8;

static H256: [u32; STATE_LEN] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Constants necessary for SHA-256 family of digests.
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn right_rotate(n: u32, d: u32) -> u32 {
    (n >> d) | (n << (32 - d))
}

pub fn sha256(message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut h0 = H256[0];
    let mut h1 = H256[1];
    let mut h2 = H256[2];
    let mut h3 = H256[3];
    let mut h4 = H256[4];
    let mut h5 = H256[5];
    let mut h6 = H256[6];
    let mut h7 = H256[7];

    let mut padded = [message, &[0x80]].concat();
    let mut suffix = vec![];
    if padded.len() % 64 < 56 {
        suffix.resize(56 - (padded.len() % 64), 0u8);
    } else {
        suffix.resize(64 + 56 - (padded.len() % 64), 0u8);
    }
    padded = [padded, suffix].concat();

    // append length
    let length = (message.len() * 8) as u64;
    padded = [padded, length.to_be_bytes().to_vec()].concat();

    // handle 512 bits at once
    for item in padded.chunks(64) {
        let mut w: Vec<u32> = vec![];
        // message schedule first to get W
        for i in 0..16 {
            w.push(u32::from_be_bytes(
                item[i * 4..i * 4 + 4].try_into().unwrap(),
            ));
        }
        w.resize(64, 0);
        for i in 16..64 {
            let s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // 64 round compression
        for i in 0..64 {
            let s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K32[i])
                .wrapping_add(w[i]);
            let s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        // update state
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }
    let hash_bytes = [h0, h1, h2, h3, h4, h5, h6, h7];
    // digest
    let mut hash: Vec<u8> = vec![];
    for h in hash_bytes.iter() {
        hash.extend(h.to_be_bytes().to_vec());
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let hash = sha256(&[0x61, 0x62, 0x63]).unwrap();
        println!("{hash:?}");
    }
}
