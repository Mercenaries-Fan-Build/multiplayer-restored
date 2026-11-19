/* multiplayer_restored.h — what multiplayer_restored.asi exports to other mods.
 *
 * The ASI's one export besides DllMain is the multiplayer-server session the player signed in with this
 * run, so another mod can call the server's REST API as that player (Authorization: Bearer <token>).
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

/* Every string is NUL-terminated UTF-8, and every byte after its NUL is zero. */
typedef struct {
    /* Set by the caller to sizeof(MrSessionV1) (836) before the call. */
    uint32_t struct_size;
    /* The server's base URL from the ASI's ini, canonical: https://host[:port][/prefix], the port only when
     * it is not 443, no trailing slash. Append an API route such as "/v1/..." to it. */
    char server_base_url[256];
    /* The bearer token of the session. The server sets its lifetime and answers an expired or revoked one
     * with HTTP 401; this export does not know about expiry. Never log it. */
    char token[512];
    /* The account's username as the server spells it (the game's displayName). */
    char username[64];
} MrSessionV1;

#ifdef __cplusplus
#define MR_STATIC_ASSERT static_assert
#else
#define MR_STATIC_ASSERT _Static_assert
#endif
MR_STATIC_ASSERT(sizeof(MrSessionV1) == 836, "MrSessionV1 is 836 bytes");
MR_STATIC_ASSERT(offsetof(MrSessionV1, server_base_url) == 4, "server_base_url at 4");
MR_STATIC_ASSERT(offsetof(MrSessionV1, token) == 260, "token at 260");
MR_STATIC_ASSERT(offsetof(MrSessionV1, username) == 772, "username at 772");

/* Returns
 *    1  signed in: the game's online `acct Login` succeeded this run and no Mp.Logout has followed;
 *       *out holds the session.
 *    0  not signed in (also while the ASI is still starting up); *out is all zero except struct_size.
 *   -1  out is NULL, or out->struct_size is not sizeof(MrSessionV1): nothing is written (only the first
 *       four bytes are read);
 *       or a value does not fit its field with its NUL (values are never truncated), or an internal error:
 *       *out is all zero except struct_size. The reason goes to multiplayer_restored.log.
 *
 * Thread-safe: any thread may call it at any time. It never blocks on the network. */
typedef int(__cdecl *mr_session_v1_fn)(MrSessionV1 *out);
int __cdecl mr_session_v1(MrSessionV1 *out);

#ifdef __cplusplus
}
#endif

#endif /* MULTIPLAYER_RESTORED_H */
