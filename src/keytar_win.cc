#include "keytar.h"

#include <windows.h>
#include <wincred.h>
#include <mutex>

namespace keytar {

LPWSTR utf8ToWideChar(std::string utf8) {
  int wide_char_length = MultiByteToWideChar(CP_UTF8,
                                             0,
                                             utf8.c_str(),
                                             -1,
                                             NULL,
                                             0);
  if (wide_char_length == 0) {
    return NULL;
  }

  LPWSTR result = new WCHAR[wide_char_length];
  if (MultiByteToWideChar(CP_UTF8,
                          0,
                          utf8.c_str(),
                          -1,
                          result,
                          wide_char_length) == 0) {
    delete[] result;
    return NULL;
  }

  return result;
}
std::string getErrorMessage(DWORD errorCode) {
  LPVOID errBuffer;
  ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  NULL, errorCode, 0, (LPTSTR) &errBuffer, 0, NULL);
  std::string errMsg = std::string(reinterpret_cast<char*>(errBuffer));
  LocalFree(errBuffer);
  return errMsg;
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                 const std::string& account,
                 const std::string& password,
                 const std::string& targetname,
                 const int credType,
                 const int credPersist,
                 std::string* errStr) {
  std::string target_name = service + '/' + account;
  if (targetname.empty()) {
    target_name = service + '/' + account;
  } else {
    target_name = targetname;
  }
  static std::mutex mutex;
  std::lock_guard<std::mutex> lock(mutex);
  if (targetname.empty()) {
    CREDENTIAL cred = { 0 };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<char*>(target_name.c_str());
    cred.CredentialBlobSize = password.size();
    cred.CredentialBlob = (LPBYTE)(password.data());
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    bool result = ::CredWrite(&cred, 0);
    if (!result) {
      *errStr = getErrorMessage(::GetLastError());
      return FAIL_ERROR;
    } else {
      return SUCCESS;
    }
  }
  CREDENTIALW cred = { 0 };
  // cred.Type = CRED_TYPE_GENERIC;
  // cred.Type = CRED_TYPE_DOMAIN_PASSWORD;
  cred.Type = static_cast<DWORD>(credType);
  // cred.TargetName = const_cast<char*>(target_name.c_str());
  cred.TargetName = utf8ToWideChar(target_name);
  // cred.UserName = const_cast<char*>(account.c_str());
  cred.UserName = utf8ToWideChar(account);
  // cred.CredentialBlobSize = password.size();
  // cred.CredentialBlobSize = static_cast<DWORD>((password.size()) + 1) * sizeof(WCHAR);

  LPWSTR temp = utf8ToWideChar(password);
  cred.CredentialBlobSize = static_cast<DWORD>(wcslen(temp) * sizeof(WCHAR));
  cred.CredentialBlob = (LPBYTE)(temp);
  // cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  cred.Persist = static_cast<DWORD>(credPersist);

  bool result = ::CredWriteW(&cred, 0);
  if (!result) {
    *errStr = getErrorMessage(::GetLastError());
    return FAIL_ERROR;
  } else {
    return SUCCESS;
  }
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                 const std::string& account,
                 std::string* password,
                 std::string* errStr) {
  std::string target_name = service + '/' + account;

  CREDENTIAL* cred;
  bool result = ::CredRead(target_name.c_str(), CRED_TYPE_GENERIC, 0, &cred);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    } else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  *password = std::string(reinterpret_cast<char*>(cred->CredentialBlob),
                          cred->CredentialBlobSize);
  ::CredFree(cred);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                    const std::string& account,
                    std::string* errStr) {
  std::string target_name = service + '/' + account;

  bool result = ::CredDelete(target_name.c_str(), CRED_TYPE_GENERIC, 0);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    } else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                  std::string* password,
                  std::string* errStr) {
  std::string filter = service + "*";

  DWORD count;
  CREDENTIAL** creds;
  bool result = ::CredEnumerate(filter.c_str(), 0, &count, &creds);
  if (!result) {
    DWORD code = ::GetLastError();
    if (code == ERROR_NOT_FOUND) {
      return FAIL_NONFATAL;
    } else {
      *errStr = getErrorMessage(code);
      return FAIL_ERROR;
    }
  }

  *password = std::string(reinterpret_cast<char*>(creds[0]->CredentialBlob),
                          creds[0]->CredentialBlobSize);
  ::CredFree(creds);
  return SUCCESS;
}

}  // namespace keytar
