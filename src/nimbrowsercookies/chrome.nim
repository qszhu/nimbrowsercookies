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
  # TODO: other oses
  getEnv("HOME") / "Library" / "Application Support" / "Google" / "Chrome" / "Default"

proc getChromePassword(): string =
  # TODO: native implementation
  let cmd = "security find-generic-password -w -s \"Chrome Safe Storage\""
  execProcess(cmd).strip

proc decryptValue(encrypted, pass: string): string =
  let encrypted = encrypted[3 .. ^1]

  # TODO: other oses
  const salt = "saltysalt"
  const keyLen = 16
  const iterations = 1003

  let key = pbkdf2(pass, salt, iterations, keyLen)

  let iv = " ".repeat(keyLen)
  result = aes.decrypt(encrypted, key, iv)

proc readCookiesFromChrome*(dbFileName, host: string): StringTableRef =
  let pass = getChromePassword()
  if pass.len == 0:
    raise newException(ValueError, "Failed to get chrome password")

  result = newStringTable()
  let db = open(dbFileName, "", "", "")
  for row in db.rows(
    sql"SELECT name, encrypted_value FROM cookies WHERE host_key LIKE ? and length(encrypted_value) > 0",
    &"%{host}"
  ):
    result[row[0]] = decryptValue(row[1], pass)
  db.close



when isMainModule:
  import std/cmdline
  echo readCookiesFromChrome(paramStr(1), paramStr(2))
