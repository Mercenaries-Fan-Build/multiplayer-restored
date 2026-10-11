//! The ProtoSSL ref (`0x128` bytes) and the game-visible contract our replacements keep.
//!
//! Layout (P, disassembly of `0x9d9910`–`0x9daa30`): `+0x00` SocketT*, `+0x04` async DNS job, `+0x08`
//! memgroup, `+0x0c` hostname (≤255 chars, copied by Connect up to the first `:`), `+0x10c` sockaddr
//! (`+0x10c` family u16 = 2, `+0x10e` port big-endian, `+0x110` IPv4 big-endian), `+0x11c` state,
//! `+0x120` closed flag, `+0x124` secure-state block (NULL for a plain connection).
//!
//! States: 1 DNS, 2 connect, 3 connecting, 0x14–0x1a handshake, 0x1e secure connected, 0x1f plain
//! connected, ≥0x1000 failure (0x1002 = connect failed). Reset (`0x9d8070`) leaves state 0 and closed=1;
//! Update clears closed when the socket connects (`0x9da5d4`).
//!
//! Return codes the callers depend on (ProtoAries `FUN_009cd3f0`, ProtoHttp `FUN_009ce730`):
//! * Stat `'stat'`: −1 when state ≥ 0x1000, 0 while connecting, > 0 (the socket reports 1) once
//!   0x1e/0x1f (`0x9daa81`–`0x9daaad`);
//! * Send: state 0x1e → `min(len, 16000)` accepted; 0x1f → raw send result; anything else −1; `len < 0`
//!   means `strlen(buf)` (`0x9da8ce`);
//! * Recv: connected → bytes copied (0 when none), and a NUL written at `buf[n]` when `0 < n < len`
//!   (`0x9daa19`); not connected → −1.

/// Size of a ref (`push 0x128` in Create).
pub const REF_SIZE: usize = 0x128;

pub const OFF_SOCKET: usize = 0x00;
pub const OFF_HOSTNAME: usize = 0x0c;
pub const HOSTNAME_MAX: usize = 0xff;
pub const OFF_SOCKADDR: usize = 0x10c;
pub const OFF_STATE: usize = 0x11c;
pub const OFF_CLOSED: usize = 0x120;
pub const OFF_SECURE: usize = 0x124;

pub const ST_IDLE: u32 = 0;
pub const ST_CONNECTING: u32 = 3;
pub const ST_SECURE: u32 = 0x1e;
pub const ST_PLAIN: u32 = 0x1f;
pub const ST_FAIL_CONNECT: u32 = 0x1002;
pub const ST_FAILURE_MIN: u32 = 0x1000;

/// Largest payload a secure Send accepts per call (`cmp esi,0x3e80` @ `0x9da903`).
pub const SECURE_SEND_MAX: usize = 16000;

/// Four-character Stat selectors, as the game passes them (little-endian dword of the reversed tag).
pub const SEL_STAT: u32 = 0x7374_6174; // 'stat'
pub const SEL_SOCK: u32 = 0x736f_636b; // 'sock'
pub const SEL_PEER: u32 = 0x7065_6572; // 'peer'
pub const SEL_BIND: u32 = 0x6269_6e64; // 'bind'

pub fn selector_name(sel: u32) -> String {
    let b = sel.to_be_bytes();
    if b.iter().all(|c| c.is_ascii_graphic()) {
        format!("'{}'", String::from_utf8_lossy(&b))
    } else {
        format!("{sel:#010x}")
    }
}

/// Typed view over one ref's bytes.
pub struct RefView<'a>(pub &'a mut [u8; REF_SIZE]);

impl RefView<'_> {
    fn rd(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().expect("4 bytes"))
    }
    fn wr(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub fn socket(&self) -> u32 {
        self.rd(OFF_SOCKET)
    }
    pub fn state(&self) -> u32 {
        self.rd(OFF_STATE)
    }
    pub fn set_state(&mut self, s: u32) {
        self.wr(OFF_STATE, s);
    }
    pub fn closed(&self) -> u32 {
        self.rd(OFF_CLOSED)
    }
    pub fn set_closed(&mut self, c: bool) {
        self.wr(OFF_CLOSED, c as u32);
    }
    pub fn secure_block(&self) -> u32 {
        self.rd(OFF_SECURE)
    }

    /// What Connect writes before choosing DNS or connect: the hostname (up to `:`/NUL, ≤255 chars,
    /// NUL-terminated) and the sockaddr (family 2, port, IPv4).
    pub fn write_target(&mut self, host: &[u8], ip: u32, port: u16) {
        let n = host.len().min(HOSTNAME_MAX);
        self.0[OFF_HOSTNAME..OFF_HOSTNAME + n].copy_from_slice(&host[..n]);
        self.0[OFF_HOSTNAME + n] = 0;
        let sa = &mut self.0[OFF_SOCKADDR..OFF_SOCKADDR + 16];
        sa.fill(0);
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        sa[4..8].copy_from_slice(&ip.to_be_bytes());
    }

    pub fn hostname(&self) -> &[u8] {
        let h = &self.0[OFF_HOSTNAME..OFF_HOSTNAME + HOSTNAME_MAX + 1];
        &h[..h.iter().position(|&b| b == 0).unwrap_or(HOSTNAME_MAX)]
    }

    pub fn sockaddr_port(&self) -> u16 {
        u16::from_be_bytes([self.0[OFF_SOCKADDR + 2], self.0[OFF_SOCKADDR + 3]])
    }

    pub fn sockaddr_ip(&self) -> u32 {
        u32::from_be_bytes(self.0[OFF_SOCKADDR + 4..OFF_SOCKADDR + 8].try_into().expect("4 bytes"))
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state(), ST_SECURE | ST_PLAIN)
    }
}

/// The game's Connect argument `name`: the host part (bytes up to the first `:` or NUL, at most 255) and
/// the `:port` override if present (Connect parses it with atoi, `0x9d9aeb`).
pub fn split_connect_name(name: &[u8]) -> (&[u8], Option<u16>) {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let name = &name[..end];
    let host_end = name.iter().position(|&b| b == b':').unwrap_or(name.len()).min(HOSTNAME_MAX);
    let port = if name.get(host_end) == Some(&b':') {
        let digits: Vec<u8> = name[host_end + 1..].iter().copied().take_while(u8::is_ascii_digit).collect();
        std::str::from_utf8(&digits).ok().and_then(|s| s.parse::<u16>().ok())
    } else {
        None
    };
    (&name[..host_end], port)
}

/// Stat `'stat'` for a ref we serve (`0x9daa81`–`0x9daaad` with a socket that reports 1 when connected).
pub fn stat_value(state: u32) -> i32 {
    if state >= ST_FAILURE_MIN {
        -1
    } else if matches!(state, ST_SECURE | ST_PLAIN) {
        1
    } else {
        0
    }
}

/// How many of `len` bytes a Send in `state` accepts, or −1.
pub fn send_accepts(state: u32, len: usize) -> i32 {
    match state {
        ST_SECURE => len.min(SECURE_SEND_MAX) as i32,
        ST_PLAIN => len.min(i32::MAX as usize) as i32,
        _ => -1,
    }
}

/// Copy up to `buf.len()` bytes from `pending` into `buf` with the Recv contract; returns the result
/// code. `closed` = the virtual connection has ended (no more bytes will ever arrive).
pub fn recv_into(state: u32, pending: &mut std::collections::VecDeque<u8>, closed: bool, buf: &mut [u8]) -> i32 {
    if !matches!(state, ST_SECURE | ST_PLAIN) {
        return -1;
    }
    let n = pending.len().min(buf.len()).min(i32::MAX as usize);
    if n == 0 {
        return if closed { -1 } else { 0 };
    }
    for (dst, src) in buf.iter_mut().zip(pending.drain(..n)) {
        *dst = src;
    }
    if n < buf.len() {
        buf[n] = 0;
    }
    n as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn layout_offsets_match_the_exe() {
        // Connect @0x9d9a3d: lea ecx,[esi+0x10c]; mov word [ecx],2; mov word [esi+0x10e],bx;
        // mov [esi+0x110],ebx. Update @0x9da598: mov dword [esi+0x11c],3. Disconnect @0x9d9b87:
        // cmp [eax+0x124],ebx. Hostname loop @0x9d9a7e: mov [edi+esi+0xc],al; cmp edi,0xff.
        let exe = crate::testdata::read_exe("mercs2_unpacked.exe");
        let at = |va: usize, bytes: &[u8]| assert_eq!(&exe[va - 0x400000..va - 0x400000 + bytes.len()], bytes);
        at(0x9d9a3d, &[0x8d, 0x8e, 0x0c, 0x01, 0x00, 0x00]);
        at(0x9d9a49, &[0x66, 0x89, 0x9e, 0x0e, 0x01, 0x00, 0x00]);
        at(0x9d9a50, &[0x89, 0x9e, 0x10, 0x01, 0x00, 0x00]);
        at(0x9da598, &[0xc7, 0x86, 0x1c, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
        at(0x9d9b87, &[0x39, 0x98, 0x24, 0x01, 0x00, 0x00]);
        at(0x9d9a76, &[0x81, 0xff, 0xff, 0x00, 0x00, 0x00]);
        at(0x9d9a7e, &[0x88, 0x44, 0x37, 0x0c]);
        // Stat selector constants as pushed by ProtoAries (0x9cd5b1 'stat', 0x9cd5e7 'peer', 0x9cd5fe 'bind').
        at(0x9cd5b1, &[0x68, 0x74, 0x61, 0x74, 0x73]);
        at(0x9cd5e7, &[0x68, 0x72, 0x65, 0x65, 0x70]);
        at(0x9cd5fe, &[0x68, 0x64, 0x6e, 0x69, 0x62]);
        assert_eq!(u32::from_le_bytes([0x74, 0x61, 0x74, 0x73]), SEL_STAT);
        assert_eq!(u32::from_le_bytes([0x72, 0x65, 0x65, 0x70]), SEL_PEER);
        assert_eq!(u32::from_le_bytes([0x64, 0x6e, 0x69, 0x62]), SEL_BIND);
        assert_eq!(u32::from_le_bytes([0x6b, 0x63, 0x6f, 0x73]), SEL_SOCK);
    }

    #[test]
    fn write_target_matches_connect() {
        let mut mem = [0xaau8; REF_SIZE];
        let mut r = RefView(&mut mem);
        r.write_target(b"fesl.ea.com", 0x7f00_0001, 18710);
        assert_eq!(r.hostname(), b"fesl.ea.com");
        assert_eq!(&r.0[OFF_SOCKADDR..OFF_SOCKADDR + 8], &[2, 0, 0x49, 0x16, 127, 0, 0, 1]);
        assert_eq!(&r.0[OFF_SOCKADDR + 8..OFF_SOCKADDR + 16], &[0; 8]);
        assert_eq!(r.sockaddr_port(), 18710);
        assert_eq!(r.sockaddr_ip(), 0x7f00_0001);
    }

    #[test]
    fn connect_name_split() {
        assert_eq!(split_connect_name(b"fesl.ea.com\0junk"), (&b"fesl.ea.com"[..], None));
        assert_eq!(split_connect_name(b"host:18710"), (&b"host"[..], Some(18710)));
        assert_eq!(split_connect_name(b""), (&b""[..], None));
    }

    #[test]
    fn stat_contract() {
        assert_eq!(stat_value(ST_IDLE), 0);
        assert_eq!(stat_value(ST_CONNECTING), 0);
        assert_eq!(stat_value(ST_SECURE), 1);
        assert_eq!(stat_value(ST_PLAIN), 1);
        assert_eq!(stat_value(ST_FAIL_CONNECT), -1);
    }

    #[test]
    fn send_contract() {
        assert_eq!(send_accepts(ST_SECURE, 20000), 16000);
        assert_eq!(send_accepts(ST_SECURE, 10), 10);
        assert_eq!(send_accepts(ST_PLAIN, 20000), 20000);
        assert_eq!(send_accepts(ST_CONNECTING, 10), -1);
        assert_eq!(send_accepts(ST_FAIL_CONNECT, 10), -1);
    }

    #[test]
    fn recv_contract() {
        let mut q: VecDeque<u8> = b"abc".iter().copied().collect();
        let mut buf = [0xffu8; 8];
        assert_eq!(recv_into(ST_SECURE, &mut q, false, &mut buf), 3);
        assert_eq!(&buf[..4], b"abc\0");
        assert_eq!(recv_into(ST_SECURE, &mut q, false, &mut buf), 0);
        assert_eq!(recv_into(ST_SECURE, &mut q, true, &mut buf), -1);
        assert_eq!(recv_into(ST_CONNECTING, &mut q, false, &mut buf), -1);
        // Exactly-full read: no NUL past the end.
        let mut q: VecDeque<u8> = b"abcd".iter().copied().collect();
        let mut buf = [0xffu8; 4];
        assert_eq!(recv_into(ST_PLAIN, &mut q, false, &mut buf), 4);
        assert_eq!(&buf, b"abcd");
    }
}
