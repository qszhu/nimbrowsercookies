# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/



import std/[
  os,
  strformat,
  strtabs,
]

import db_connector/db_sqlite

import pkg/nimtestcrypto

when defined macosx:
  import std/[
    osproc,
    strutils,
  ]
elif defined windows:
  import std/[
    base64,
    json,
  ]
  import dpapi

export strtabs



proc getChromeDefaultProfilePath*(): string {.inline.} =
  when defined linux:
    getEnv("HOME") / ".config" / "google-chrome" / "Default"
  elif defined macosx:
    getEnv("HOME") / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
  elif defined windows:
    getEnv("LOCALAPPDATA") / "Google" / "Chrome" / "User Data" / "Default"
  else:
    raise newException(ValueError, "Unsupported platform")

proc getCookieFn*(profilePath: string): string {.inline.} =
  when defined windows:
    profilePath / "Network" / "Cookies"
  else:
    profilePath / "Cookies"

proc getChromeKey(profilePath: string): string =
  when defined linux:
    return "peanuts"
  elif defined macosx:
    # TODO: native implementation
    let cmd = "security find-generic-password -w -s \"Chrome Safe Storage\""
    return execProcess(cmd).strip
  elif defined windows:
    let jso = readFile(profilePath / ".." / "Local State").parseJson
    let key = jso["os_crypt"]["encrypted_key"].getStr.decode
    doAssert key[0 ..< 5] == "DPAPI"
    let decrypted = dpapi.decrypt(cast[seq[uint8]](key[5 .. ^1]))
    let res = cast[string](decrypted)
    return res[0 ..< res.len]
  else:
    raise newException(ValueError, "Unsupported platform")

proc decryptValue(encrypted, key: string): string =
  if encrypted.len == 0: return

  let passVer = encrypted[0 ..< 3]
  if passVer != "v10":
    raise newException(ValueError, "Unsupported password version: " & passVer)

  var encrypted = encrypted[3 .. ^1]
  when defined linux:
    const iterations = 1
  elif defined macosx:
    const iterations = 1003
  elif defined windows:
    let iv = encrypted[0 ..< 12]
    encrypted = encrypted[12 .. ^1]
  else:
    raise newException(ValueError, "Unsupported platform")

  when defined windows:
    return cast[string](aes.decryptAES256GCM(
      cast[seq[uint8]](encrypted),
      cast[seq[uint8]](key),
      cast[seq[uint8]](iv)
    ))
  else:
    const salt = "saltysalt"
    const keyLen = 16
    let key = pbkdf2(key, salt, iterations, keyLen)
    let iv = " ".repeat(keyLen)
    return cast[string](aes.decryptAES128CBC(
      cast[seq[uint8]](encrypted),
      cast[seq[uint8]](key),
      cast[seq[uint8]](iv)
    ))

proc readCookiesFromChrome*(profilePath, host: string): StringTableRef =
  result = newStringTable()
  let key = getChromeKey(profilePath)
  let dbFn = getCookieFn(profilePath)
  echo dbFn
  let db = open(dbFn, "", "", "")
  for row in db.rows(
    sql"SELECT name, encrypted_value FROM cookies WHERE host_key LIKE ?",
    &"%{host}"
  ):
    result[row[0]] = decryptValue(row[1], key)
  db.close




when isMainModule:
  import std/cmdline

  for k, v in readCookiesFromChrome(paramStr(1), paramStr(2)):
    echo (k, v)
