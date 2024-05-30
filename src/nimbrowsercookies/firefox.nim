import std/[
  os,
  strformat,
  tables,
  tempfiles,
]

import db_connector/db_sqlite

export tables



proc readCookiesFromFirefox*(dbFileName: string, host: string): Table[string, string] =
  let (_, copyFn) = createTempfile("", ".sqlite")
  try:
    writeFile(copyFn, readFile(dbFileName))
    let db = open(copyFn, "", "", "")
    for row in db.getAllRows(
      sql"SELECT name, value FROM moz_cookies WHERE host LIKE ?",
      &"%{host}"
    ):
      result[row[0]] = row[1]
    db.close
  finally:
    removeFile(copyFn)
