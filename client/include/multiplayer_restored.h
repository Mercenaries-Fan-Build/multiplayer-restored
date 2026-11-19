/* multiplayer_restored.h — what multiplayer_restored.asi exports to other mods.
 *
 * The ASI's one export besides DllMain says who is signed in to the multiplayer server this run: whether the
 * player holds a session, the account id, the username and when the session expires. The session token never
 * leaves the ASI; the leaderboards (Net.LeaderboardGetScore, Net.LeaderboardPushScore) run inside it.
 *
 * The ASI is not an import library. A mod resolves the export at run time, when it needs it, not in its
 * own DllMain, because the order the game's plugin loader loads ASIs in is not guaranteed:
 *
 *     HMODULE mr = GetModuleHandleA("multiplayer_restored.asi");
 *     mr_session_v1_fn get =
 *         mr ? (mr_session_v1_fn)(void (*)(void))GetProcAddress(mr, "mr_session_v1") : NULL;
 *     MrSessionV1 s;
 *     memset(&s, 0, sizeof s);
 *     s.struct_size = sizeof s;
 *     int r = get ? get(&s) : -2;   // -2 here: the ASI is not loaded, or predates this export
 *
 * A mod that needs it declares the dependency in its Shipment manifest
 * (`load.requires: - { shipment: multiplayer-restored, version: ">=0.6.0" }`).
 *
 * Versioning: the struct carries its own size, and the function name carries the version. A new field
 * means a new MrSessionV2 and mr_session_v2; MrSessionV1 and mr_session_v1 never change.
 */
#ifndef MULTIPLAYER_RESTORED_H
#define MULTIPLAYER_RESTORED_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Every field sits at a multiple of its own size: no padding, whatever the compiler's alignment of int64_t. */
typedef struct {
    /* Set by the caller to sizeof(MrSessionV1) (88) before the call. */
    uint32_t struct_size;
    /* 1 signed in, 0 not (the same as the return value). */
    uint32_t signed_in;
    /* The account's user id on the server. */
    int64_t account_id;
    /* When the server ends the session, in Unix seconds. */
    int64_t expires_at;
    /* The account's username as the server spells it (the game's displayName): NUL-terminated UTF-8, every
     * byte after the NUL zero. */
    char username[64];
} MrSessionV1;

#ifdef __cplusplus
#define MR_STATIC_ASSERT static_assert
#else
#define MR_STATIC_ASSERT _Static_assert
#endif
MR_STATIC_ASSERT(sizeof(MrSessionV1) == 88, "MrSessionV1 is 88 bytes");
MR_STATIC_ASSERT(offsetof(MrSessionV1, signed_in) == 4, "signed_in at 4");
MR_STATIC_ASSERT(offsetof(MrSessionV1, account_id) == 8, "account_id at 8");
MR_STATIC_ASSERT(offsetof(MrSessionV1, expires_at) == 16, "expires_at at 16");
MR_STATIC_ASSERT(offsetof(MrSessionV1, username) == 24, "username at 24");

/* Returns
 *    1  signed in: the game's online `acct Login` succeeded this run and no Mp.Logout has followed;
 *       *out holds the session.
 *    0  not signed in (also while the ASI is still starting up); *out is all zero except struct_size.
 *   -1  out is NULL, or out->struct_size is not sizeof(MrSessionV1): nothing is written (only the first
 *       four bytes are read);
 *       or the username does not fit its field with its NUL (it is never truncated), or an internal error:
 *       *out is all zero except struct_size. The reason goes to multiplayer_restored.log.
 *
 * Thread-safe: any thread may call it at any time. It never blocks on the network. */
typedef int(__cdecl *mr_session_v1_fn)(MrSessionV1 *out);
int __cdecl mr_session_v1(MrSessionV1 *out);

#ifdef __cplusplus
}
#endif

#endif /* MULTIPLAYER_RESTORED_H */
