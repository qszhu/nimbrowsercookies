# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
import std/[
  os,
  osproc,
  strformat,
  strutils,
  tables,
]

import db_connector/db_sqlite

import pkg/nimtestcrypto

export tables



proc getDefaultChromeProfilePath*(): string {.inline.} =
  # TODO: other oses
  getEnv("HOME") / "Library" / "Application Support" / "Google" / "Chrome" / "Default"

proc getChromePassword(): string =
  # TODO: native implementation
  let cmd = "security find-generic-password -w -s \"Chrome Safe Storage\""
  execProcess(cmd).strip

proc decryptValue(encrypted: string): string =
  let encrypted = encrypted[3 .. ^1]

  # TODO: other oses
  const salt = "saltysalt"
  const keyLen = 16
  const iterations = 1003

  let pass = getChromePassword()
  if pass.len == 0:
    raise newException(ValueError, "Failed to get chrome password")

  let key = pbkdf2(pass, salt, iterations, keyLen)

  let iv = " ".repeat(keyLen)
  result = aes.decrypt(encrypted, key, iv)

proc readCookiesFromChrome*(dbFileName: string, host: string): Table[string, string] =
  let db = open(dbFileName, "", "", "")
  for row in db.getAllRows(
    sql"SELECT name, encrypted_value FROM cookies WHERE host_key LIKE ?",
    &"%{host}"
  ):
    result[row[0]] = decryptValue(row[1])
  db.close
