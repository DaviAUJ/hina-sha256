use std::{
    cmp,
    iter::once,
    arch::x86_64 as asm,
};

const K_HELPER: [u32; 64] = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone)]
pub struct Sha256Hash([u32; 8]);

#[derive(Debug, Clone)]
pub struct Sha256Builder {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    h5: u32,
    h6: u32,
    h7: u32,
    
    byte_len:     usize,
    active_chunk: [u8; 64],
}

impl Sha256Hash {
    pub fn new<T: AsRef<[u8]>>(data: T) -> Self {
        let data   = data.as_ref();
        let chunks = data.as_chunks::<64>();

        let mut h0 = 0x6a09e667_u32;
        let mut h1 = 0xbb67ae85_u32;
        let mut h2 = 0x3c6ef372_u32;
        let mut h3 = 0xa54ff53a_u32;
        let mut h4 = 0x510e527f_u32;
        let mut h5 = 0x9b05688c_u32;
        let mut h6 = 0x1f83d9ab_u32;
        let mut h7 = 0x5be0cd19_u32;
        
        let (first, second) = format_rem_chunk(chunks.1, (data.len() * 8) as u64);
        
        let iter = chunks
            .0
            .iter()
            .map(|c| format_chunk(c))
            .chain(once(first))
            .chain(second);
        
        for chunk in iter {
            let w = make_w(&chunk);
    
            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;
            let mut f = h5;
            let mut g = h6;
            let mut h = h7;
            
            for idx in 0..64 {
                let s1    = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch    = (e & f) ^ (!e & g);
                let temp1 = h + s1 + ch + K_HELPER[idx] + w[idx];
                let s0    = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj   = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0 + maj;
        
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;
        }

        Self([h0, h1, h2, h3, h4, h5, h6, h7])
    }

    pub fn as_upper_hex(&self) -> String {
        self
            .0
            .iter()
            .map(|n| format!("{:08X}", n))
            .collect()
    }
    
    pub fn as_lower_hex(&self) -> String {
        self
            .0
            .iter()
            .map(|n| format!("{:08x}", n))
            .collect()
    }
}

impl Sha256Builder {
    pub fn new() -> Self {
        Self {
            h0: 0x6a09e667,
            h1: 0xbb67ae85,
            h2: 0x3c6ef372,
            h3: 0xa54ff53a,
            h4: 0x510e527f,
            h5: 0x9b05688c,
            h6: 0x1f83d9ab,
            h7: 0x5be0cd19,

            byte_len:     0,
            active_chunk: [0; _],
        }
    }

    pub fn add<T: AsRef<[u8]>>(mut self, data: T) -> Self {
        let data       = data.as_ref();
        let active_len = self.byte_len % 64;
        let active_rem = 64 - active_len;
        let copy_len   = cmp::min(active_rem, data.len());
        
        self.byte_len += data.len();
        self.active_chunk[active_len..active_len+copy_len].copy_from_slice(&data[..copy_len]);

        let uncp_data = &data[copy_len..];
        let (full_chunks, rem) = uncp_data.as_chunks::<64>();

        if active_len + copy_len == 64 {
            let fchunk = format_chunk(&self.active_chunk);
            self.chunk_round(&fchunk);
            self.active_chunk[..rem.len()].copy_from_slice(rem);
        }
        
        for chunk in full_chunks {
            let fchunk = format_chunk(chunk);
            self.chunk_round(&fchunk);
        }

        self
    }

    pub fn sum(mut self) -> Sha256Hash {
        let active_len = self.byte_len % 64;

        let (first, second) = format_rem_chunk(&self.active_chunk[..active_len], self.byte_len as u64 * 8);
        
        self.chunk_round(&first);
        if let Some(chunk) = second {
            self.chunk_round(&chunk);
        }

        Sha256Hash([
            self.h0, 
            self.h1, 
            self.h2, 
            self.h3, 
            self.h4, 
            self.h5, 
            self.h6, 
            self.h7, 
        ])
    }

    // #[cfg(feature = "hw-accel")]
    // fn chunk_round(&mut self, chunk: &[u32; 16]) {
    //     
    // }

    // #[cfg(not(feature = "hw-accel"))]
    fn chunk_round(&mut self, chunk: &[u32; 16]) {
        let w = make_w(chunk);

        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;
        let mut f = self.h5;
        let mut g = self.h6;
        let mut h = self.h7;
        
        for idx in 0..64 {
            let s1    = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch    = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + K_HELPER[idx] + w[idx];
            let s0    = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj   = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;
    
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        self.h0 += a;
        self.h1 += b;
        self.h2 += c;
        self.h3 += d;
        self.h4 += e;
        self.h5 += f;
        self.h6 += g;
        self.h7 += h;
    }
}

#[cfg(feature = "hw-accel")]
fn make_w(chunk: &[u32; 16]) -> [u32; 64] {
    let mut out = [0; _];

    out[0..16].copy_from_slice(chunk);

    unsafe {
        for idx in (16..64).step_by(4) {
            let addr = out.as_ptr().add(idx * 4) as * const i32;
            
            let msg1 = asm::_mm_loadu_epi32(addr);
            
        }
        
    }
    
    out
}

#[cfg(not(feature = "hw-accel"))]
fn make_w(chunk: &[u32; 16]) -> [u32; 64] {
    let mut out = [0; _];

    out[0..16].copy_from_slice(chunk);

    for idx in 16..64 {
        let s0 = {
            let x = out[idx - 15];
            
            x.rotate_right(7) ^ x.rotate_right(18) ^ x.unbounded_shr(3)
        };
        
        let s1 = {
            let x = out[idx - 2];

            x.rotate_right(17) ^ x.rotate_right(19) ^ x.unbounded_shr(10)
        };

        out[idx] = out[idx - 16] + s0 + out[idx - 7] + s1;
    }
    
    out
}

fn format_chunk(data: &[u8; 64]) -> [u32; 16] {
    let mut out = [0; _];
    let iter = data
        .as_chunks::<4>()
        .0
        .iter()
        .zip(out.iter_mut());

    for (bytes, word) in iter {
        *word = u32::from_be_bytes(*bytes);
    }

    out
}

fn format_rem_chunk(data: &[u8], msg_bitlen: u64) -> ([u32; 16], Option<[u32; 16]>) {
    let mut bytes  = [0u8; 64];
    let mut second = None; 
    let mut first;

    if data.len() > 63 {
        panic!("The data provided has length {}. It should be no more than 63", data.len());
    }

    bytes[..data.len()].copy_from_slice(data);
    bytes[data.len()] = 1 << 7;
    first = format_chunk(&bytes);
    
    if data.len() < 56 {
        first[14] = ((msg_bitlen & 0xFFFFFFFF00000000) >> 32) as u32;
        first[15] = (msg_bitlen & 0xFFFFFFFF) as u32;
    }
    else {
        let mut inner = [0; _];

        inner[14] = ((msg_bitlen & 0xFFFFFFFF00000000) >> 32) as u32;
        inner[15] = (msg_bitlen & 0xFFFFFFFF) as u32;
        
        second = Some(inner);
    }
    
    (first, second)
}

fn chunk_padding(data: &[u32]) -> [u32; 16] {
    let mut out  = [0; _];
    let     last = cmp::min(16, data.len());

    out[..last].copy_from_slice(&data[..last]);
    
    out
}