# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/



import std/[
  os,
  strformat,
  strtabs,
  tempfiles,
]

import db_connector/db_sqlite

import pkg/nimtestcrypto

when defined macosx:
  import std/[
    base64,
    strutils,
  ]
  import macos
elif defined windows:
  import std/[
    base64,
    json,
  ]
  import dpapi

export strtabs, os



proc getCookieFn*(profilePath: string): string {.inline.} =
  when defined windows:
    profilePath / "Network" / "Cookies"
  else:
    profilePath / "Cookies"

proc getChromeKey(profilePath: string): string =
  when defined linux:
    return "peanuts"
  elif defined macosx:
    return base64.encode(getPassword("Chrome Safe Storage", "Chrome").get)
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

proc readCookiesFromChromium*(profilePath, host: string): StringTableRef =
  result = newStringTable()
  let key = getChromeKey(profilePath)
  let dbFn = getCookieFn(profilePath)
  let (_, copyFn) = createTempFile("", "")
  try:
    copyFile(dbFn, copyFn)
    let db = open(copyFn, "", "", "")
    for row in db.rows(
      sql"SELECT name, encrypted_value FROM cookies WHERE host_key LIKE ?",
      &"%{host}"
    ):
      result[row[0]] = decryptValue(row[1], key)
    db.close
  finally:
    removeFile(copyFn)
