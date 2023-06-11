use jni::JNIEnv;
use jni::sys::{jbyteArray, jclass};
use crate::data::*;
use rand::{Rng, RngCore};

// 'byte[] xyz.cssxsh.mirai.tool.TLV544Provider.sign$fix_protocol_version(long, byte[])'
#[no_mangle]
pub extern "system" fn Java_xyz_cssxsh_mirai_tool_TLV544Provider_sign_00024fix_1protocol_1version(
    env: JNIEnv, _this: jclass, payload: jbyteArray,
) -> jbyteArray {
    let bytes = env.convert_byte_array(payload).unwrap();
    let curr = std::time::UNIX_EPOCH.elapsed().unwrap().as_micros();
    let r = sign(curr as _, bytes.as_slice());
    env.byte_array_from_slice(&r).unwrap() as _
}

#[no_mangle]
unsafe extern "C" fn sign_bytes(ptr: *const u8, len: usize, buf: *mut [u8; 39]) {
    let curr = std::time::UNIX_EPOCH.elapsed().unwrap().as_micros();
    buf.write(sign(curr as u64, std::slice::from_raw_parts(ptr, len)));
}

pub fn sign(mut time: u64, bytes: &[u8]) -> [u8; 39] {
    if time > 1000000 {
        time %= 1000000;
    }
    let curr_bytes: [u8; 4] = (time as u32).to_le_bytes();

    let mut bytes = bytes.to_vec();
    bytes.extend(curr_bytes);

    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(time);
    fn gen_idx<R: Rng>(r: &mut R) -> usize {
        r.gen_range(0usize..50)
    }

    let mut key_table = [0u8; 40];
    for i in [0, 1] {
        key_table[i] = KEY_TABLE[gen_idx(&mut rng)] + 50;
    }

    for i in [1, 2] {
        key_table[i + 1] = key_table[i] + 20;
    }

    let mut ks = [0u8; 4];
    ks.copy_from_slice(&key_table[..4]);

    let k3 = &mut key_table[4..14];
    k3[2..2 + 4].copy_from_slice(&KEY1[..4]);
    for i in 0..4 {
        k3[i + 2 + 4] = KEY2[i] ^ ks[i];
    }
    for i in [0, 1] {
        k3[i] = std::mem::take(&mut k3[i + 8]);
    }

    let key = <&mut [u8; 8]>::try_from(&mut k3[..8]).unwrap();
    let rc_key = rc4::Key::from(*key);
    let mut cipher = <rc4::Rc4<_> as rc4::KeyInit>::new(&rc_key);
    rc4::StreamCipher::apply_keystream(&mut cipher, key);

    let mut crc_dat = [0u8; 21];
    crc_dat[4..12].copy_from_slice(&CRC_PART);

    let part_k = <&mut [u8; 32]>::try_from(&mut key_table[4..4 + 32]).unwrap();
    let part_crc = <&mut [u8; 8]>::try_from(&mut crc_dat[4..4 + 8]).unwrap();
    tencent_enc_a(&mut bytes, part_k, part_crc);
    let mut md5_core = <md5::Md5 as md5::Digest>::new();
    md5::Digest::update(&mut md5_core, bytes);
    let md5_result = md5::Digest::finalize(md5_core);
    crc_dat[2] = 1;
    crc_dat[3] = curr_bytes[3];
    crc_dat[4] = 1;
    crc_dat[5..5 + 4].copy_from_slice(&key_table[..4]);
    crc_dat[9..9 + 4].copy_from_slice(&(time as u32).to_be_bytes());
    crc_dat[13..13 + 8].copy_from_slice(&md5_result[..8]);
    let crc32 = tencent_crc_32(&CRC_TABLE, (&crc_dat[2..]).try_into().unwrap());
    key_table[36..36 + 4].copy_from_slice(&crc32.to_le_bytes());
    crc_dat[0] = key_table[36];
    crc_dat[1] = key_table[39];

    let nbytes: [u8; 4] = (rng.next_u32() ^ rng.next_u32() ^ rng.next_u32()).to_be_bytes();
    key_table[..4].copy_from_slice(&nbytes);

    for i in [4, 8] {
        let k = &mut key_table[..i << 1];
        let (l, r) = k.split_at_mut(i);
        r.copy_from_slice(l);
    }

    let mut out = [0u8; 39];
    out.copy_from_slice(&key_table[..39]);
    transform_encode(&mut crc_dat);
    let mut enc_dat = [0; 21];
    tencent_enc_b(
        (&mut key_table[..16]).try_into().unwrap(),
        &crc_dat,
        &mut enc_dat,
    );
    transform_decode(&mut enc_dat);
    out[0] = 12;
    out[1] = 5;
    out[2..2 + 4].copy_from_slice(&nbytes);
    out[6..6 + 21].copy_from_slice(&enc_dat);
    out[27..27 + 4].fill(0);
    out[31] = TABLE2[gen_idx(&mut rng)];
    out[32] = TABLE2[gen_idx(&mut rng)];
    let mut add = rng.gen_range(0u8..8);
    add |= 0b1;
    out[33] = out[31] + add;
    out[34] = out[32] + 9 - add + 1;
    out[35..35 + 4].fill(0);

    out
}

#[no_mangle]
unsafe extern "C" fn sub_ad_c(ptr: *mut [u32; 16]) {
    sub_ad(&mut *ptr);
}

fn sub_ad(st: &mut [u32; 16]) {
    let mut r12 = st[3];
    let mut dx = st[4];
    let mut bp = st[11];
    let mut r15 = st[0].wrapping_add(dx);
    let r9 = (st[12] ^ r15).rotate_left(16);
    let si = st[5];
    let mut r11 = st[8].wrapping_add(r9);
    let mut r14 = st[1].wrapping_add(si);
    let mut r8 = (st[13] ^ r14).rotate_left(16);
    let mut cx = st[6];
    let mut r13 = st[2].wrapping_add(cx);
    let mut bx = st[9].wrapping_add(r8);
    let mut di = (st[14] ^ r13).rotate_left(16);
    let mut r10 = st[10].wrapping_add(di);
    dx = (dx ^ r11).rotate_left(12);
    r15 = r15.wrapping_add(dx);
    let mut r9 = (r9 ^ r15).rotate_left(8);
    let mut si = (si ^ bx).rotate_left(12);
    r14 = r14.wrapping_add(si);
    cx = (cx ^ r10).rotate_left(12);
    r11 = r11.wrapping_add(r9);
    r8 ^= r14;
    r13 = r13.wrapping_add(cx);
    r8 = r8.rotate_left(8);
    bx = bx.wrapping_add(r8);
    di = (di ^ r13).rotate_left(8);
    let tmp0 = (dx ^ r11).rotate_left(7);
    let mut dx = st[7];
    si ^= bx;
    let tmp1 = bx;
    let mut bx = r10;
    si = si.rotate_left(7);
    bx = bx.wrapping_add(di);
    r12 = r12.wrapping_add(dx);
    r15 = r15.wrapping_add(si);
    r10 = (st[15] ^ r12).rotate_left(16);
    cx = (cx ^ bx).rotate_left(7);
    bp = bp.wrapping_add(r10);
    r14 = r14.wrapping_add(cx);
    dx = (dx ^ bp).rotate_left(12);
    r9 = (r9 ^ r14).rotate_left(16);
    r12 = r12.wrapping_add(dx);
    let r10 = (r10 ^ r12).rotate_left(8);
    let bp = bp.wrapping_add(r10);
    let r10 = (r10 ^ r15).rotate_left(16);
    let bx = bx.wrapping_add(r10);
    let si = (si ^ bx).rotate_left(12);
    let r15 = r15.wrapping_add(si);
    st[0] = r15;
    let r10 = (r10 ^ r15).rotate_left(8);
    let bx = bx.wrapping_add(r10);
    st[15] = r10;
    st[10] = bx;
    let dx = (dx ^ bp).rotate_left(7);
    let bp = bp.wrapping_add(r9);
    let cx = (cx ^ bp).rotate_left(12);
    let r13 = r13.wrapping_add(dx);
    let r14 = r14.wrapping_add(cx);
    st[5] = (si ^ bx).rotate_left(7);
    let r8 = (r8 ^ r13).rotate_left(16);
    st[1] = r14;
    let r11 = r11.wrapping_add(r8);
    let r9 = (r9 ^ r14).rotate_left(8);
    let bp = bp.wrapping_add(r9);
    st[12] = r9;
    let dx = (dx ^ r11).rotate_left(12);
    st[11] = bp;
    let r13 = r13.wrapping_add(dx);
    st[6] = (cx ^ bp).rotate_left(7);
    let r8 = (r8 ^ r13).rotate_left(8);
    st[2] = r13;
    let r11 = r11.wrapping_add(r8);
    st[8] = r11;
    st[7] = (dx ^ r11).rotate_left(7);
    st[13] = r8;
    r12 = r12.wrapping_add(tmp0);
    di ^= r12;
    di = di.rotate_left(16);
    let cx = tmp1.wrapping_add(di);
    let dx = (tmp0 ^ cx).rotate_left(12);
    r12 = r12.wrapping_add(dx);
    di ^= r12;
    st[3] = r12;
    let rd = di.rotate_left(8);
    st[14] = rd;
    let cx = cx.wrapping_add(rd);
    st[4] = (dx ^ cx).rotate_left(7);
    st[9] = cx;
}

#[derive(Default, Debug)]
struct State {
    state: [u32; 16],
    org_state: [u32; 16],
    nr: u8,
    p: u8,
}

fn tencent_crc_32(table: &CrcTable, bytes: &[u8]) -> u32 {
    if bytes.len() == 0 {
        return 0;
    }

    let mut crc = u32::MAX;
    for &val in bytes {
        let mut val = val;
        val ^= crc as u8;
        // val is less then or equals 255
        crc = (crc >> 8) ^ table[val as usize];
    }

    !crc
}

fn tencent_enc_a(input: &mut [u8], key: &[u8; 32], data: &[u8; 8]) {
    let mut state = State::default();
    state_init(&mut state, key, data, 0, 20);
    encrypt(&mut state, input);
}

fn tencent_enc_b(ktb: &mut [u8; 16], crc: &[u8; 21], output: &mut [u8; 21]) {
    let mut buf = [0u8; 16];

    for (i, out) in output.iter_mut().enumerate() {
        if i & 15 == 0 {
            buf.copy_from_slice(ktb);
            _tencent_enc_b(&mut buf, &ENC_TRB);
            for j in ktb.iter_mut().rev() {
                *j = j.wrapping_add(1);
                if *j != 0 {
                    break;
                }
            }
        }
        *out = sub_aa(i, &ENC_TEA, &buf, crc);
    }
}

fn _tencent_enc_b(p1: &mut [u8; 16], p2: &[u32; 44]) {
    for i in 0..9 {
        permute(&IP_TABLE, p1);
        let i4 = i << 2;
        sub_b(p1, (&p2[i4..i4 + 4]).try_into().unwrap());
        sub_c(&ENC_TEB, p1);
        sub_e(&ENC_TEC, p1);
    }
    permute(&IP_TABLE, p1);
    let f4 = 10 << 2;
    sub_b(p1, (&p2[f4 - 4..f4]).try_into().unwrap());
    sub_c(&ENC_TEB, p1);
    sub_a(p1, (&p2[f4..f4 + 4]).try_into().unwrap());
}

fn sub_a(data: &mut [u8; 16], t: &[u32; 4]) {
    for (i, num) in t.clone().into_iter().enumerate() {
        let [a, b, c, d] = num.to_le_bytes();
        let [q,w,e,r, ..] = &mut data[i << 2..] else {
            unreachable!()
        };
        *q ^= d;
        *w ^= c;
        *e ^= b;
        *r ^= a;
    }
}

fn sub_b(data: &mut [u8; 16], t: &[u32; 4]) {
    let mut tb = [0u8; 16];
    for (i, &val) in t.iter().enumerate() {
        let i4 = i << 2;
        tb[i4..i4 + 4].copy_from_slice(&val.to_le_bytes());
    }

    for i in 0..4 {
        let i4 = i << 2;
        let [q,w,e,r, ..] = &mut data[i << 2..] else {
            unreachable!();
        };

        let (h, i, j, k) = ((i4 + 3) & 15, (i4 + 6) & 15, (i4 + 9) & 15, (i4 + 12) & 15);
        let (h, i, j, k) = (tb[h], tb[i], tb[j], tb[k]);

        *q ^= h;
        *w ^= i;
        *e ^= j;
        *r ^= k;
    }
}

fn sub_c(t: &[[u8; 16]; 16], data: &mut [u8; 16]) {
    for i in 0..16 {
        let datum = data[i] as usize;
        let tab = &t[datum >> 4];

        data[i] = tab[datum & 15];
    }
}

fn permute(t: &[u8; 16], p: &mut [u8; 16]) {
    let tmp = *p;

    for i in 0..16 {
        let idx = t[i] as usize; // idx < 16
        p[i] = tmp[idx];
    }
}

fn sub_e(t: &[[u8; 6]; 256], data: &mut [u8; 16]) {
    for i in 0..4 {
        let i4 = i << 2;
        let [a,b,c,d] = data[i4..i4+4] else {
            unreachable!();
        };

        let ta = t[a as usize];
        let tb = t[b as usize];
        let tc = t[c as usize];
        let td = t[d as usize];

        data[i4] = (c ^ d) ^ (ta[0] ^ tb[1]);
        data[i4 + 1] = (a ^ d) ^ (tb[0] ^ tc[1]);
        data[i4 + 2] = (a ^ b) ^ (tc[0] ^ td[1]);
        data[i4 + 3] = (b ^ c) ^ (td[0] ^ ta[1]);
    }
}

fn sub_aa(i: usize, table: &[[[[u8; 16]; 16]; 2]; 16], buf: &[u8; 16], data: &[u8]) -> u8 {
    let datum = data[i] as usize;

    let idx = i & 15;
    let bufdx = buf[idx] as usize;

    let tb = &table[idx];

    let a = tb[0][datum >> 4][bufdx >> 4] << 4;
    let b = tb[1][datum & 15][bufdx & 15];
    a ^ b
}

fn state_init(state: &mut State, key: &[u8; 32], data: &[u8; 8], counter: u64, nr: u8) {
    state.nr = nr;
    state.p = 0;
    init_state_impl(state, key, data, counter);
}

fn init_state_impl(state: &mut State, key: &[u8; 32], data: &[u8; 8], counter: u64) {
    let stat = &mut state.state;
    // 0..4
    stat[..4].copy_from_slice(&STAT_CHK);

    // 4..12
    for i in (0..32).step_by(4) {
        let i4 = i + 4;
        let kb = <[u8; 4]>::try_from(&key[i..i4]).unwrap();
        let k = u32::from_le_bytes(kb);
        stat[(i + 16) >> 2] = k;
    }

    fn put_16b(dst: &mut [u32; 2], src: &[u8; 8]) {
        let (a, b) = src.split_at(4);
        let u1 = <[u8; 4]>::try_from(a).unwrap();
        let u2 = <[u8; 4]>::try_from(b).unwrap();
        let u1 = u32::from_le_bytes(u1);
        let u2 = u32::from_le_bytes(u2);
        dst[0] = u1;
        dst[1] = u2;
    }

    // 12..14
    put_16b(
        (&mut stat[12..=13]).try_into().unwrap(),
        &counter.to_le_bytes(),
    );
    // 14..16
    put_16b((&mut stat[14..=15]).try_into().unwrap(), data);

    let org_stat = &mut state.org_state;

    for i in 0..12 {
        org_stat[i] = stat[i];
    }

    for i in 12..16 {
        org_stat[i] = rand::thread_rng().next_u32();
    }
}

fn encrypt(state: &mut State, data: &mut [u8]) {
    let mut cnt = 0;
    let mut len = data.len();

    while len > 0 {
        if state.p == 0 {
            for _ in (0..state.nr).step_by(2) {
                sub_ad(&mut state.state);
            }
            for i in 0..16 {
                state.state[i] = state.state[i].wrapping_add(state.org_state[i]);
            }
        }

        let mut sb = [0u8; 16 << 2];
        for (i, val) in state.state.into_iter().enumerate() {
            let vb = val.to_le_bytes();
            sb[i << 2..(i + 1) << 2].copy_from_slice(&vb);
        }

        while state.p <= 64 && len != 0 {
            data[cnt] ^= sb[state.p as usize];
            state.p += 1;
            cnt += 1;
            len -= 1;
        }

        if state.p >= 64 {
            state.p = 0;
            state.org_state[12] += 1;
            state.state = state.org_state;
        }
    }
}

fn transform_encode(x: &mut [u8; 21]) {
    transformer(x, &ENC_TR);
}

fn transform_decode(x: &mut [u8; 21]) {
    transformer(x, &DEC_TR);
}

fn transformer(x: &mut [u8; 21], tab: &[[u8; 16]; 32]) {
    for (i, val) in x.iter_mut().enumerate() {
        let i = i << 1;
        let e = *val as usize;

        let a = tab[i & 31][e >> 4] << 4;
        let b = tab[(i + 1) & 31][e & 15];
        *val = a ^ b;
    }
}

#[cfg(test)]
mod tests {
    use crate::data::{ENC_TEA, ENC_TEB, ENC_TEC, ENC_TRB, IP_TABLE};
    use crate::t544_sign::{
        permute, sign, state_init, sub_a, sub_aa, sub_ad, sub_b, sub_c, sub_e, tencent_crc_32,
        tencent_enc_a, tencent_enc_b, transform_encode, State, _tencent_enc_b, CRC_TABLE,
    };

    #[test]
    fn test_tc_enc_a() {
        let mut input = [0; 4];
        let key = [
            252, 116, 44, 52, 247, 132, 156, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let crc = [64, 85, 103, 196, 13, 207, 237, 110];

        tencent_enc_a(&mut input, &key, &crc);

        assert_eq!(input, [215, 5, 255, 209]);

        let mut input = [253, 15, 22, 102];
        tencent_enc_a(&mut input, &key, &crc);

        assert_eq!(input, [42, 10, 233, 183]);
    }

    #[test]
    fn test_tc_enc_b() {
        let mut buf = [
            210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 91,
        ];
        _tencent_enc_b(&mut buf, &ENC_TRB);
        assert_eq!(
            buf,
            [71, 67, 148, 199, 14, 167, 49, 35, 113, 99, 212, 182, 0, 213, 107, 214]
        );

        let mut buf = [
            210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 92,
        ];
        _tencent_enc_b(&mut buf, &ENC_TRB);
        assert_eq!(
            buf,
            [243, 65, 4, 164, 172, 162, 64, 218, 221, 224, 230, 138, 88, 226, 82, 211,]
        );

        let mut ktb = [
            210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 91, 210, 139, 64, 91,
        ];
        let crc = [
            214, 56, 32, 165, 34, 194, 140, 121, 237, 149, 29, 148, 12, 217, 253, 87, 136, 248,
            229, 203, 25,
        ];
        let mut out = [0; 21];

        tencent_enc_b(&mut ktb, &crc, &mut out);

        assert_eq!(
            out,
            [
                219, 169, 68, 203, 7, 13, 227, 94, 199, 9, 168, 23, 251, 213, 244, 227, 139, 133,
                22, 120, 139,
            ]
        );
    }

    #[test]
    fn test_sub_ad() {
        let mut a = [
            255, 125, 616, 1666, 15167, 0, 13771, 171, 0, 0, 0, 6171717, 0, 172717, 0, 0,
        ];
        sub_ad(&mut a);

        assert_eq!(
            a,
            [
                1490007296, 614008496, 1905708589, 2303990587, 5607228, 1594224743, 791947012,
                1334475872, 2696820147, 2676788890, 962874278, 2345172983, 2972549835, 3591336565,
                3906279370, 3224769161
            ]
        );
    }

    #[test]
    fn crc() {
        let data = [
            0, 0, 0, 13, 41, 0, 122, 0, 250, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let crc = tencent_crc_32(&CRC_TABLE, &data);
        assert_eq!(crc, 3648022832);

        let crc = tencent_crc_32(
            &CRC_TABLE,
            &[
                1, 0, 1, 93, 88, 108, 128, 0, 0, 0, 0, 39, 66, 158, 221, 70, 218, 150, 100,
            ],
        );
        assert_eq!(crc, 1449873289);
    }

    #[test]
    fn state() {
        let mut s = State::default();
        let key = [
            0, 12, 0, 0, 0, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];

        let data = [0, 14, 0, 224, 0, 5, 0, 0];
        state_init(&mut s, &key, &data, 0, 20);

        assert_eq!(
            s.state,
            [
                1634760805, 857760878, 2036477234, 1797285236, 3072, 54528, 0, 0, 32, 0, 0, 0, 0,
                0, 3758099968, 1280
            ]
        );
        //assert_eq!(s.state, [1634760805 857760878 2036477234 1797285236 3072 54528 0 0 32 0 0 0 0 0 3758099968 1280]);
    }

    #[test]
    fn test_sign() {
        let sign_bytes = sign(0, &[]);
        assert_eq!(
            sign_bytes,
            [
                12, 5, 98, 73, 61, 196, 202, 80, 14, 27, 244, 157, 94, 216, 205, 175, 236, 200, 98,
                151, 72, 195, 134, 64, 176, 235, 57, 0, 0, 0, 0, 107, 43, 114, 46, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_d() {
        let mut buf = [
            10, 93, 59, 150, 53, 11, 250, 10, 243, 217, 205, 64, 227, 231, 247, 208,
        ];
        permute(&IP_TABLE, &mut buf);

        assert_eq!(
            buf,
            [10, 11, 205, 208, 53, 217, 247, 150, 243, 231, 59, 10, 227, 93, 250, 64]
        );
    }

    #[test]
    fn test_trans() {
        let mut x = [
            0, 0, 12, 0, 41, 0, 55, 0, 15, 0, 125, 0, 255, 15, 0, 166, 32, 0, 151, 0, 0,
        ];

        transform_encode(&mut x);
        assert_eq!(
            x,
            [
                46, 166, 42, 165, 90, 149, 101, 149, 31, 149, 126, 148, 47, 139, 12, 75, 14, 166,
                223, 165, 45
            ]
        );
    }

    #[test]
    fn test_sub_a() {
        let mut p1 = [
            176, 23, 207, 75, 180, 229, 72, 250, 96, 213, 34, 45, 151, 23, 83, 189,
        ];
        let p2 = [1129761775, 407308320, 3174417575, 3488940398];

        sub_a(&mut p1, &p2);
        assert_eq!(
            p1,
            [243, 65, 4, 164, 172, 162, 64, 218, 221, 224, 230, 138, 88, 226, 82, 211]
        );
    }

    #[test]
    fn test_sub_b() {
        let mut p1 = [
            51, 150, 147, 5, 157, 88, 17, 187, 53, 117, 130, 53, 247, 119, 147, 74,
        ];
        let p2 = [3488618159, 1527890895, 2775764103, 1925236169];

        sub_b(&mut p1, &p2);
        assert_eq!(
            p1,
            [252, 135, 95, 204, 198, 42, 212, 20, 144, 181, 148, 250, 133, 135, 80, 205]
        );
    }

    #[test]
    fn test_sub_c() {
        let mut p1 = [
            158, 99, 181, 239, 120, 57, 186, 231, 32, 204, 147, 234, 232, 73, 18, 92,
        ];

        sub_c(&ENC_TEB, &mut p1);

        assert_eq!(
            p1,
            [11, 251, 213, 223, 188, 18, 244, 148, 183, 75, 220, 135, 155, 59, 201, 74]
        );
    }

    #[test]
    fn test_sub_e() {
        let mut p1 = [
            143, 68, 215, 214, 255, 231, 212, 158, 46, 58, 83, 43, 173, 70, 34, 249,
        ];

        sub_e(&ENC_TEC, &mut p1);

        assert_eq!(
            p1,
            [200, 179, 31, 174, 157, 211, 18, 14, 106, 132, 207, 77, 80, 190, 191, 97,]
        );
    }

    #[test]
    fn test_sub_aa() {
        let buf = [
            71, 67, 148, 199, 14, 167, 49, 35, 113, 99, 212, 182, 0, 213, 107, 214,
        ];
        let m = [
            214, 56, 32, 165, 34, 194, 140, 121, 237, 149, 29, 148, 12, 217, 253, 87, 136, 248,
            229, 203, 25,
        ];

        let b = sub_aa(0, &ENC_TEA, &buf, &m);
        assert_eq!(b, 219);
    }
}
