import std/[
  os,
  strformat,
  strtabs,
  tempfiles,
]

import db_connector/db_sqlite

export strtabs


# MacOS, Linux
proc readCookiesFromFirefox*(dbFileName, host: string): StringTableRef =
  result = newStringTable()
  let (_, copyFn) = createTempfile("", ".sqlite")
  try:
    copyFile(dbFileName, copyFn)
    let db = open(copyFn, "", "", "")
    for row in db.getAllRows(
      sql"SELECT name, value FROM moz_cookies WHERE host LIKE ?",
      &"%{host}"
    ):
      result[row[0]] = row[1]
    db.close
  finally:
    removeFile(copyFn)



when isMainModule:
  import std/cmdline
  echo readCookiesFromFirefox(paramStr(1), paramStr(2))
