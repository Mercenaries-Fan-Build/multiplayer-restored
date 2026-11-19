//! Every Lua name this ASI adds to the game, as `(table, field)`. The Windows side registers exactly these and
//! stops the game at start-up when what it registered differs.

pub const ADDED: &[(&str, &str)] = &[
    ("Mp", "GetRoomKey"),
    ("Mp", "Logout"),
    ("Mp", "SetRoomKey"),
    ("Net", "GetUserName"),
    ("Net", "LeaderboardGetScore"),
    ("Net", "LeaderboardPushScore"),
    ("Pg", "SetCheatsUsed"),
    ("Pg", "WereCheatsUsed"),
];
