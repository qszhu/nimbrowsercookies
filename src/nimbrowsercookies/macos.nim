# https://github.com/iffy/nim-keyring
{.passL: "-framework CoreFoundation".}
{.passL: "-framework Security".}

import std/[
  base64,
  options,
]

export base64, options



type
  CFTypeRef {.pure, inheritable.} = ptr object

  CFString = object of CFTypeRef
  CFStringRef = ptr object of CFString
  CFStringEncoding = distinct int

  CFBooleanRef = ptr object of CFTypeRef

  CFDataRef* = ptr object of CFTypeRef

  CFIndex = distinct int

  CFPropertyList = ptr object of CFTypeRef

  CFAbstractDictionary = ptr object of CFPropertyList
  CFDictionary = ptr object of CFAbstractDictionary
  CFDictionaryRef = ptr object of CFDictionary
  CFDictionaryKeyCallBacks = object
  CFDictionaryValueCallBacks = object

  OSStatus = cint

var
  kSecClass {.importc.}: CFStringRef
  kSecClassGenericPassword {.importc.}: CFStringRef
  kSecAttrService {.importc.}: CFStringRef
  kSecAttrAccount {.importc.}: CFStringRef
  kSecMatchLimit {.importc.}: CFStringRef
  kSecReturnData {.importc.}: CFStringRef
  kSecMatchLimitOne {.importc.}: CFStringRef
  kCFBooleanTrue {.importc.}: CFBooleanRef

const
  kCFStringEncodingISOLatin1 = (0x0201).CFStringEncoding

var
  errSecSuccess: cint
  errSecItemNotFound: cint

proc CFRelease*(cf: CFTypeRef) {.importc.}
proc CFRetain*(cf: CFTypeRef) {.importc.}

proc CFStringCreateWithCString*(alloc: pointer, str: cstring, encoding: CFStringEncoding): CFStringRef {.importc.}
proc CFDictionaryCreate*(allocator: pointer, keys: pointer, values: pointer, numValues: CFIndex, keyCallBacks: ptr CFDictionaryKeyCallBacks, valueCallBacks: ptr CFDictionaryValueCallBacks): CFDictionaryRef {.importc.}

proc CFDataGetLength(theData: CFDataRef): CFIndex {.importc.}
proc CFDataGetBytePtr(theData: CFDataRef): pointer {.importc.}

proc SecItemCopyMatching*(query: CFDictionaryRef, res: ptr CFTypeRef): OSStatus {.importc.}

proc mkCFstring(s: string): CFStringRef {.inline.} =
  CFStringCreateWithCString(nil, s.cstring, kCFStringEncodingISOLatin1)

proc getCFData*(theData: CFDataRef): string =
  if theData.isNil:
    raise newException(CatchableError, "Attempting to access nil CFDataRef")
  let length = CFDataGetLength(theData)

  result = newString(length.int)
  let p = CFDataGetBytePtr(theData)
  copyMem(result.cstring, p, length.int)

proc getPassword*(service: string, username: string): Option[string] =
  let
    key1 = kSecClass
    val1 = kSecClassGenericPassword

    k_service = kSecAttrService
    v_service = mkCFString(service)

    k_account = kSecAttrAccount
    v_account = mkCFString(username)

  var qkeys: array[5, CFStringRef] = [key1, k_service, k_account, kSecMatchLimit,    kSecReturnData]
  var qvals: array[5, CFTypeRef] =   [val1, v_service, v_account, kSecMatchLimitOne, kCFBooleanTrue]

  let qlen: CFIndex = qkeys.len.CFIndex
  let query = CFDictionaryCreate(nil, qkeys.addr, qvals.addr, qlen, nil, nil)

  var password: CFDataRef
  let err = SecItemCopyMatching(query, cast[ptr CFTypeRef](password.addr))
  CFRelease(query)
  CFRelease(v_service)
  CFRelease(v_account)

  if err == errSecSuccess:
    CFRetain(password)
    var password_string = password.getCFData().decode()
    CFRelease(password)
    result = some(password_string)
  elif err == errSecItemNotFound:
    result = none[string]()
  else:
    raise newException(CatchableError, "Error: " & $err)



when isMainModule:
  const service = "Chrome Safe Storage"
  const account = "Chrome"
  echo base64.encode(getPassword(service, account).get)
