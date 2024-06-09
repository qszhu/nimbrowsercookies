import chromium



proc getEdgeDefaultProfilePath*(): string {.inline.} =
  when defined windows:
    getEnv("LOCALAPPDATA") / "Microsoft" / "Edge" / "User Data" / "Default"
  else:
    raise newException(ValueError, "Unsupported platform")



when isMainModule:
  import std/cmdline

  for k, v in readCookiesFromChromium(getEdgeDefaultProfilePath(), paramStr(1)):
    echo (k, v)
