//! The game's Lua 5.1 stack, read and written through 32-bit addresses.
//!
//! Layout (Pandemic's build: `lua_Number` is `float`, so a `TValue` is 8 bytes):
//!
//! * `lua_State`: `top` at `+0x08`, `base` at `+0x0C` (read by every engine binding, e.g.
//!   `Net.IsOnlineConnected` `0x005CAD10` writes its result at `[L+8]` and bumps it by 8; `error()`
//!   `0x00860480` compares `[L+0xC]+8` with `[L+8]` to count arguments);
//! * `TValue`: value at `+0`, type tag at `+4` (`0x005CAD39`: `mov dword [eax+4], 1` for a boolean);
//! * `TString`: length at `+0x0C`, characters from `+0x10` (`luaS_newlstr` `0x0086A314` compares
//!   `[ts+0xC]` with the length and the bytes at `ts+0x10`).
//!
//! Type tags are Lua 5.1's (`LUA_TNIL 0`, `LUA_TBOOLEAN 1`, `LUA_TNUMBER 3`, `LUA_TSTRING 4`,
//! `LUA_TTABLE 5`, `LUA_TFUNCTION 6`); `luaG_errormsg` checks the error handler for tag 6.
//!
//! A C function may push up to `LUA_MINSTACK` (20) values without growing the stack: Lua 5.1's
//! `luaD_precall` guarantees that much room before it calls one (INFERRED for this build from the
//! stock source; every engine binding pushes its results the same way, without a stack check).
//!
//! [`Vm`] is the memory the layout lives in: the game process in the ASI, a byte arena in the tests.

pub const L_TOP: u32 = 0x08;
pub const L_BASE: u32 = 0x0C;
pub const TVALUE_SIZE: u32 = 8;
pub const TVALUE_TT: u32 = 4;
pub const TSTRING_LEN: u32 = 0x0C;
pub const TSTRING_DATA: u32 = 0x10;

pub const LUA_TNIL: u32 = 0;
pub const LUA_TBOOLEAN: u32 = 1;
pub const LUA_TNUMBER: u32 = 3;
pub const LUA_TSTRING: u32 = 4;
pub const LUA_TTABLE: u32 = 5;
pub const LUA_TFUNCTION: u32 = 6;

/// Lua's own name for a type tag, as `type()` reports it.
pub fn type_name(tag: u32) -> String {
    match tag {
        LUA_TNIL => "nil".into(),
        LUA_TBOOLEAN => "boolean".into(),
        2 => "userdata".into(),
        LUA_TNUMBER => "number".into(),
        LUA_TSTRING => "string".into(),
        LUA_TTABLE => "table".into(),
        LUA_TFUNCTION => "function".into(),
        7 => "userdata".into(),
        8 => "thread".into(),
        other => format!("type tag {other}"),
    }
}

/// The memory a `lua_State` lives in.
pub trait Vm {
    fn read_u32(&self, addr: u32) -> u32;
    fn write_u32(&mut self, addr: u32, value: u32);
    fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8>;
    /// The game's `luaS_newlstr(L, bytes, len)`: an interned Lua string, returned as its `TString*`.
    fn new_string(&mut self, l: u32, bytes: &[u8]) -> u32;
}

/// One argument, as the bindings need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    Nil,
    Str(Vec<u8>),
    /// Any other type, by tag.
    Other(u32),
}

/// The stack of the `lua_State` at `l`.
pub struct Stack<'a, V: Vm> {
    vm: &'a mut V,
    l: u32,
}

impl<'a, V: Vm> Stack<'a, V> {
    pub fn new(vm: &'a mut V, l: u32) -> Self {
        Stack { vm, l }
    }

    fn top(&self) -> u32 {
        self.vm.read_u32(self.l + L_TOP)
    }

    fn base(&self) -> u32 {
        self.vm.read_u32(self.l + L_BASE)
    }

    /// `lua_gettop`: the number of arguments the function was called with (before any push).
    pub fn arg_count(&self) -> u32 {
        (self.top() - self.base()) / TVALUE_SIZE
    }

    /// Argument `i`, 1-based. `i` beyond [`Stack::arg_count`] reads as `nil`, as in Lua.
    pub fn arg(&self, i: u32) -> Arg {
        if i == 0 || i > self.arg_count() {
            return Arg::Nil;
        }
        let at = self.base() + (i - 1) * TVALUE_SIZE;
        match self.vm.read_u32(at + TVALUE_TT) {
            LUA_TNIL => Arg::Nil,
            LUA_TSTRING => {
                let ts = self.vm.read_u32(at);
                let len = self.vm.read_u32(ts + TSTRING_LEN);
                Arg::Str(self.vm.read_bytes(ts + TSTRING_DATA, len))
            }
            tag => Arg::Other(tag),
        }
    }

    fn push(&mut self, value: u32, tag: u32) {
        let top = self.top();
        self.vm.write_u32(top, value);
        self.vm.write_u32(top + TVALUE_TT, tag);
        self.vm.write_u32(self.l + L_TOP, top + TVALUE_SIZE);
    }

    pub fn push_nil(&mut self) {
        self.push(0, LUA_TNIL);
    }

    pub fn push_bool(&mut self, b: bool) {
        self.push(b as u32, LUA_TBOOLEAN);
    }

    pub fn push_string(&mut self, s: &[u8]) {
        let ts = self.vm.new_string(self.l, s);
        self.push(ts, LUA_TSTRING);
    }
}

#[cfg(test)]
pub(crate) mod arena {
    //! A fake process: one byte buffer addressed from `BASE`, holding a `lua_State`, its stack and the
    //! strings, with the exact offsets of [`super`].
    use super::*;

    pub const BASE: u32 = 0x1000_0000;
    pub const L: u32 = BASE;
    pub const STACK: u32 = BASE + 0x100;
    pub const STRINGS: u32 = BASE + 0x1000;

    pub struct Arena {
        pub mem: Vec<u8>,
        next_string: u32,
    }

    impl Arena {
        /// A state whose frame holds `args` (each a `(value, tag)` or a string).
        pub fn with_args(args: &[ArenaArg]) -> Arena {
            let mut a = Arena { mem: vec![0; 0x4000], next_string: STRINGS };
            a.write_u32(L + 4, 8); // tt = LUA_TTHREAD, as in a real state
            a.write_u32(L + L_BASE, STACK);
            a.write_u32(L + L_TOP, STACK);
            for arg in args {
                let top = a.read_u32(L + L_TOP);
                let (v, tag) = match arg {
                    ArenaArg::Nil => (0, LUA_TNIL),
                    ArenaArg::Num => (0x3f80_0000, LUA_TNUMBER),
                    ArenaArg::Table => (0xdead_0000, LUA_TTABLE),
                    ArenaArg::Str(s) => (a.new_string(L, s.as_bytes()), LUA_TSTRING),
                };
                a.write_u32(top, v);
                a.write_u32(top + TVALUE_TT, tag);
                a.write_u32(L + L_TOP, top + TVALUE_SIZE);
            }
            a
        }

        /// The values pushed above the arguments, as `(tag, payload)`; strings are read back.
        pub fn results(&self, nargs: u32) -> Vec<(u32, Option<String>, u32)> {
            let base = self.read_u32(L + L_BASE);
            let top = self.read_u32(L + L_TOP);
            let mut out = Vec::new();
            let mut at = base + nargs * TVALUE_SIZE;
            while at < top {
                let tag = self.read_u32(at + TVALUE_TT);
                let v = self.read_u32(at);
                let s = (tag == LUA_TSTRING).then(|| {
                    let len = self.read_u32(v + TSTRING_LEN);
                    String::from_utf8(self.read_bytes(v + TSTRING_DATA, len)).unwrap()
                });
                out.push((tag, s, v));
                at += TVALUE_SIZE;
            }
            out
        }
    }

    pub enum ArenaArg {
        Nil,
        Num,
        Table,
        Str(&'static str),
    }

    impl Vm for Arena {
        fn read_u32(&self, addr: u32) -> u32 {
            let o = (addr - BASE) as usize;
            u32::from_le_bytes(self.mem[o..o + 4].try_into().unwrap())
        }
        fn write_u32(&mut self, addr: u32, value: u32) {
            let o = (addr - BASE) as usize;
            self.mem[o..o + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
            let o = (addr - BASE) as usize;
            self.mem[o..o + len as usize].to_vec()
        }
        fn new_string(&mut self, l: u32, bytes: &[u8]) -> u32 {
            assert_eq!(l, L, "luaS_newlstr is called with the state");
            // TString: 16-byte header (len at +0xC), the characters, a NUL.
            let ts = self.next_string;
            self.write_u32(ts + TSTRING_LEN, bytes.len() as u32);
            let o = (ts + TSTRING_DATA - BASE) as usize;
            self.mem[o..o + bytes.len()].copy_from_slice(bytes);
            self.mem[o + bytes.len()] = 0;
            self.next_string = (ts + TSTRING_DATA + bytes.len() as u32 + 1 + 7) & !7;
            ts
        }
    }
}

#[cfg(test)]
mod tests {
    use super::arena::*;
    use super::*;

    #[test]
    fn reads_arguments_by_tag() {
        let mut a = Arena::with_args(&[ArenaArg::Str("venezuela-42"), ArenaArg::Nil, ArenaArg::Num, ArenaArg::Table]);
        let s = Stack::new(&mut a, L);
        assert_eq!(s.arg_count(), 4);
        assert_eq!(s.arg(1), Arg::Str(b"venezuela-42".to_vec()));
        assert_eq!(s.arg(2), Arg::Nil);
        assert_eq!(s.arg(3), Arg::Other(LUA_TNUMBER));
        assert_eq!(s.arg(4), Arg::Other(LUA_TTABLE));
        assert_eq!(s.arg(5), Arg::Nil, "beyond the frame reads as nil");
        assert_eq!(s.arg(0), Arg::Nil);
    }

    #[test]
    fn pushes_land_at_top_with_lua_tags() {
        let mut a = Arena::with_args(&[ArenaArg::Str("x")]);
        {
            let mut s = Stack::new(&mut a, L);
            s.push_bool(false);
            s.push_string(b"a message");
            s.push_nil();
            s.push_bool(true);
            assert_eq!(s.arg_count(), 5);
        }
        let r = a.results(1);
        assert_eq!(r.len(), 4);
        assert_eq!((r[0].0, r[0].2), (LUA_TBOOLEAN, 0));
        assert_eq!((r[1].0, r[1].1.as_deref()), (LUA_TSTRING, Some("a message")));
        assert_eq!(r[2].0, LUA_TNIL);
        assert_eq!((r[3].0, r[3].2), (LUA_TBOOLEAN, 1));
    }

    #[test]
    fn type_names_are_luas() {
        assert_eq!(type_name(LUA_TNUMBER), "number");
        assert_eq!(type_name(LUA_TTABLE), "table");
        assert_eq!(type_name(42), "type tag 42");
    }
}
