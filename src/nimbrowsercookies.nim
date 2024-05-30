import std/[
  os,
]

import nimbrowsercookies/[chrome, firefox, types]

export chrome, firefox, types



proc readCookies*(browser: Browser, profilePath, host: string): StringTableRef =
  case browser
  of Browser.FIREFOX:
    let dbFn = profilePath / "cookies.sqlite"
    readCookiesFromFirefox(dbFn, host)
  of Browser.CHROME:
    let dbFn = profilePath / "Cookies"
    readCookiesFromChrome(dbFn, host)
