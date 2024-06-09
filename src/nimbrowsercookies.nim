import nimbrowsercookies/[chromium, chrome, edge, firefox, types]

export chromium, chrome, edge, firefox, types



proc readCookies*(browser: Browser, profilePath, host: string): StringTableRef =
  case browser
  of Browser.FIREFOX:
    readCookiesFromFirefox(profilePath, host)
  of Browser.CHROME, Browser.EDGE:
    readCookiesFromChromium(profilePath, host)
