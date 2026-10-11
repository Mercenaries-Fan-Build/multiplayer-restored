-- [multiplayer-restored] The Multiplayer submenu, appended to the front end's mrxguishell
-- (patch_lua, session: front_end).
--
-- shell.gfx fires the FSCommand `friendsLobbyEntered` when the player opens the friends lobby;
-- CompleteFlashSetup binds it to the global _EnterFriendsLobbyFlashCallback each time the movie
-- loads. This append replaces that global, so the event opens this menu instead. "Back" (also the
-- cancel button) runs retail's handler, so the friends lobby is entered exactly as before.
--
-- Mp.GetRoomKey / Mp.SetRoomKey are registered by multiplayer_restored.asi on every Lua state the
-- script host creates. The menu is MrxMultiPageMenu (a paged MrxGui.DisplayDialogBox) and the key
-- editor is MrxGuiNumericBox, called the way retail's wager box calls it (mrxbriefing.lua:1215).
-- The numeric box edits a 7-digit number (Lua numbers are floats here: 7 digits stay exact), which
-- becomes a 7-character key; a key with letters can still be set in multiplayer_restored.ini.
import("MrxGuiNumericBox")

_MpRetailEnterFriendsLobby = _EnterFriendsLobbyFlashCallback
_knMpKeyDigits = 7
_knMpKeyMax = 9999999

function _MpRoomKeyLabel()
  local sKey = Mp.GetRoomKey()
  if sKey == nil then
    return "Public"
  end
  return sKey
end

function _MpOpenMenu(oFlash, sArg)
  oFlash:SetVisible(false)
  MrxMultiPageMenu.Reset()
  MrxMultiPageMenu.AddOption("Room key: " .. _MpRoomKeyLabel(), _MpOpenRoomKeyMenu, {oFlash, sArg}, false)
  MrxMultiPageMenu.AddOption("Back", _MpBack, {oFlash, sArg}, true, true)
  MrxMultiPageMenu.Display("Multiplayer")
end

function _MpBack(oFlash, sArg)
  oFlash:SetVisible(true)
  _MpRetailEnterFriendsLobby(oFlash, sArg)
end

function _MpOpenRoomKeyMenu(oFlash, sArg)
  MrxMultiPageMenu.Reset()
  MrxMultiPageMenu.AddOption("Enter a 7-digit key", _MpEnterKey, {oFlash, sArg}, false)
  MrxMultiPageMenu.AddOption("Clear (public games only)", _MpClearKey, {oFlash, sArg}, false)
  MrxMultiPageMenu.AddOption("Back", _MpOpenMenu, {oFlash, sArg}, true, true)
  MrxMultiPageMenu.Display("Room key: " .. _MpRoomKeyLabel())
end

function _MpClearKey(oFlash, sArg)
  Mp.SetRoomKey(nil)
  _MpOpenMenu(oFlash, sArg)
end

function _MpEnterKey(oFlash, sArg)
  local sKey = Mp.GetRoomKey()
  local nDefault = 0
  if sKey and string.len(sKey) == _knMpKeyDigits and string.find(sKey, "^%d+$") then
    nDefault = tonumber(sKey)
  end
  MrxGuiNumericBox.DisplayNumericBox(Player.GetLocalPlayer(), "Room key", nil, "", "", nDefault, 0, _knMpKeyMax, _knMpKeyDigits - 1, 0, _knMpKeyDigits - 1, _MpKeyAccepted, {oFlash, sArg}, _MpOpenRoomKeyMenu, {oFlash, sArg}, 48, 36, "right", "bottom", false)
end

function _MpKeyAccepted(oFlash, sArg, nValue)
  local sKey = string.format("%0" .. _knMpKeyDigits .. "d", nValue)
  local bOk, sMessage = Mp.SetRoomKey(sKey)
  if bOk then
    _MpOpenMenu(oFlash, sArg)
  else
    MrxMultiPageMenu.Reset()
    MrxMultiPageMenu.AddOption("OK", _MpOpenRoomKeyMenu, {oFlash, sArg}, true, true)
    MrxMultiPageMenu.Display("Room key " .. sKey .. " refused: " .. tostring(sMessage))
  end
end

function _EnterFriendsLobbyFlashCallback(oFlash, sArg)
  _MpOpenMenu(oFlash, sArg)
end
