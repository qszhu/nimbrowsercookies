# https://gist.github.com/akamajoris/ed2f14d817d5514e7548
# https://github.com/khchen/winim/blob/master/winim/inc/wincrypt.nim



type
  BYTE = uint8
  DWORD = int32
  WINBOOL = int32

  WCHAR = uint16
  LPWSTR = ptr WCHAR
  LPCWSTR = ptr WCHAR

  HANDLE = int
  HLOCAL = HANDLE
  HWND = HANDLE

  PVOID = pointer

proc LocalFree(
  hMem: HLOCAL
): HLOCAL {.discardable, stdcall, dynlib: "kernel32", importc.}



const
  CRYPTPROTECT_UI_FORBIDDEN = 0x1

type
  CRYPT_INTEGER_BLOB = object
    cbData: DWORD
    pbData: ptr BYTE

  DATA_BLOB = CRYPT_INTEGER_BLOB

  CRYPTPROTECT_PROMPTSTRUCT = object
    cbSize: DWORD
    dwPromptFlags: DWORD
    hwndApp: HWND
    szPrompt: LPCWSTR

proc CryptProtectData(
  pDataIn: ptr DATA_BLOB,
  szDataDescr: LPCWSTR,
  pOptionalEntropy: ptr DATA_BLOB,
  pvReserved: PVOID,
  pPromptStruct: ptr CRYPTPROTECT_PROMPTSTRUCT,
  dwFlags: DWORD,
  pDataOut: ptr DATA_BLOB
): WINBOOL {.discardable, stdcall, dynlib: "crypt32", importc.}

proc CryptUnprotectData(
  pDataIn: ptr DATA_BLOB,
  ppszDataDescr: ptr LPWSTR,
  pOptionalEntropy: ptr DATA_BLOB,
  pvReserved: PVOID,
  pPromptStruct: ptr CRYPTPROTECT_PROMPTSTRUCT,
  dwFlags: DWORD,
  pDataOut: ptr DATA_BLOB
): WINBOOL {.discardable, stdcall, dynlib: "crypt32", importc.}



proc newDataBlob(d: seq[uint8]): DATA_BLOB =
  DATA_BLOB(
    cbData: d.len.DWORD,
    pbData: addr(d[0]),
  )

proc toBytes(d: var CRYPT_INTEGER_BLOB): seq[uint8] =
  result = newSeq[uint8](d.cbData)
  copyMem(addr(result[0]), d.pbData, result.len)

proc encrypt*(data: seq[uint8]): seq[uint8] =
  var dataIn = newDataBlob(data)
  var dataOut: CRYPT_INTEGER_BLOB
  CryptProtectData(addr(dataIn), nil, nil, nil, nil, CRYPTPROTECT_UI_FORBIDDEN, addr(dataOut))
  result = dataOut.toBytes
  LocalFree(cast[HLOCAL](dataOut.pbData))

proc decrypt*(data: seq[uint8]): seq[uint8] =
  var dataIn = newDataBlob(data)
  var dataOut: CRYPT_INTEGER_BLOB
  CryptUnProtectData(addr(dataIn), nil, nil, nil, nil, CRYPTPROTECT_UI_FORBIDDEN, addr(dataOut))
  result = dataOut.toBytes
  LocalFree(cast[HLOCAL](dataOut.pbData))



when isMainModule:
  let secret = "Hello World"
  let encrypted = encrypt(cast[seq[uint8]](secret))
  echo encrypted.len
  let decrypted = decrypt(encrypted)
  let s = cast[string](decrypted)
  echo (s.len, s)