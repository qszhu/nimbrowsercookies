# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
import std/[
  os,
  osproc,
  strformat,
  strtabs,
  strutils,
]

import db_connector/db_sqlite

import pkg/nimtestcrypto

export strtabs



proc getDefaultChromeProfilePath*(): string {.inline.} =
  when defined linux:
    getEnv("HOME") / ".config" / "google-chrome" / "Default"
  elif defined macosx:
    getEnv("HOME") / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
  else:
    raise newException(ValueError, "Unsupported platform")

proc getChromePassword(): string =
  # TODO: native implementation
  let cmd = "security find-generic-password -w -s \"Chrome Safe Storage\""
  execProcess(cmd).strip

proc decryptValue(encrypted, pass: string): string =
  if encrypted.len == 0: return

  let passVer = encrypted[0 ..< 3]
  if passVer != "v10":
    raise newException(ValueError, "Unsupported password version: " & passVer)

  let encrypted = encrypted[3 .. ^1]

  const salt = "saltysalt"
  const keyLen = 16
  when defined linux:
    const iterations = 1
  elif defined macosx:
    const iterations = 1003
  else:
    raise newException(ValueError, "Unsupported platform")

  let key = pbkdf2(pass, salt, iterations, keyLen)

  let iv = " ".repeat(keyLen)
  result = aes.decrypt(encrypted, key, iv)

proc readCookiesFromChrome*(dbFileName, host: string): StringTableRef =
  when defined linux:
    let pass = "peanuts"
  elif defined macosx:
    let pass = getChromePassword()
    if pass.len == 0:
      raise newException(ValueError, "Failed to get chrome password")
  else:
    raise newException(ValueError, "Unsupported platform")

  result = newStringTable()
  let db = open(dbFileName, "", "", "")
  for row in db.rows(
    sql"SELECT name, encrypted_value FROM cookies WHERE host_key LIKE ?",
    &"%{host}"
  ):
    result[row[0]] = decryptValue(row[1], pass)
  db.close



when isMainModule:
  import std/cmdline
  echo readCookiesFromChrome(paramStr(1), paramStr(2))
