"""Guest-only thread UI language state derived from the configured persona."""

from __future__ import annotations

import locale


_LANGIDS = {
    tag.casefold().replace("_", "-"): lcid & 0xFFFF
    for lcid, tag in locale.windows_locale.items()
    if 0 < lcid <= 0xFFFF
}
_KNOWN_LANGIDS = frozenset(_LANGIDS.values())


class ThreadUILanguage:
    def __init__(self, persona: dict):
        self.unsupported: list[str] = []
        tag = str(persona["locale"]).casefold().replace("_", "-")
        self.default = _LANGIDS.get(tag)
        if self.default is None:
            self.default = 0x0409
            self.unsupported.append(
                f"UI language for persona locale {persona['locale']!r} is unknown; using en-US")
        self._by_thread: dict[int, int] = {}
        self._console_filter_threads: set[int] = set()

    def install(self, emulator) -> None:
        for module in ("kernel32", "api-ms-win-core-localization-l1-2-0"):
            emulator.add_api_hook(self._set, module, "SetThreadUILanguage", argc=1)
            emulator.add_api_hook(self._get, module, "GetThreadUILanguage", argc=0)
            emulator.add_api_hook(self._user, module, "GetUserDefaultUILanguage", argc=0)
            emulator.add_api_hook(self._set_preferred, module,
                                  "SetThreadPreferredUILanguages", argc=3)
        emulator.add_api_hook(self._set,
                              "ext-ms-win-fsutilext-ulib-l1-1-0",
                              "SetThreadUILanguageStub", argc=1)

    def _set_preferred(self, emu, api_name, _original, params) -> int:
        flags, languages, count = map(int, params)
        if flags == 0x100 and not languages and not count:  # MUI_CONSOLE_FILTER
            thread = emu.get_current_thread()
            if thread is not None:
                self._console_filter_threads.add(id(thread))
            emu.set_last_error(0)
            return 1
        self.unsupported.append(f"{api_name}: language list or flags unsupported")
        emu.set_last_error(87)
        return 0

    def _set(self, emu, api_name, _original, params) -> int:
        requested = int(params[0])
        if requested == 0:
            requested = self.default
        elif requested not in _KNOWN_LANGIDS:
            self.unsupported.append(f"{api_name}: unsupported LANGID {requested:#x}")
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return self._get(emu, api_name, None, [])
        thread = emu.get_current_thread()
        if thread is not None:
            self._by_thread[id(thread)] = requested
        return requested

    def _get(self, emu, _api_name, _original, _params) -> int:
        thread = emu.get_current_thread()
        return self._by_thread.get(id(thread), self.default)

    def _user(self, _emu, _api_name, _original, _params) -> int:
        return self.default
