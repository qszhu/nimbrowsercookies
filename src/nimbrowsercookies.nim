import nimbrowsercookies/[chromium, firefox, types]

export chromium, firefox, types



proc readCookies*(browser: Browser, profilePath, host: string): StringTableRef =
  case browser
  of Browser.FIREFOX:
    readCookiesFromFirefox(profilePath, host)
  of Browser.CHROME, Browser.EDGE:
    readCookiesFromChromium(profilePath, host)
