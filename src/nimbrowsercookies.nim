import nimbrowsercookies/[chrome, firefox, types]

export chrome, firefox, types



proc readCookies*(browser: Browser, dbFileName, host: string): StringTableRef =
  case browser
  of Browser.FIREFOX:
    readCookiesFromFirefox(dbFileName, host)
  of Browser.CHROME:
    readCookiesFromChrome(dbFileName, host)
