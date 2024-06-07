import std/[
  os,
]

import nimbrowsercookies/[chrome, firefox, types]

export chrome, firefox, types



proc readCookies*(browser: Browser, profilePath, host: string): StringTableRef =
  case browser
  of Browser.FIREFOX:
    readCookiesFromFirefox(profilePath, host)
  of Browser.CHROME:
    readCookiesFromChrome(profilePath, host)
