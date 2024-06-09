import chromium



proc getChromeDefaultProfilePath*(): string {.inline.} =
  when defined linux:
    getEnv("HOME") / ".config" / "google-chrome" / "Default"
  elif defined macosx:
    getEnv("HOME") / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
  elif defined windows:
    getEnv("LOCALAPPDATA") / "Google" / "Chrome" / "User Data" / "Default"
  else:
    raise newException(ValueError, "Unsupported platform")


when isMainModule:
  import std/cmdline

  for k, v in readCookiesFromChromium(getChromeDefaultProfilePath(), paramStr(1)):
    echo (k, v)
