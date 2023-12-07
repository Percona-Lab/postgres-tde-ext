
#ifndef KEYRING_CURL_H
#define KEYRING_CURL_H

#include "pg_tde_defines.h"

#include <stdbool.h>
#include <curl/curl.h>

typedef struct curlString {
  char *ptr;
  size_t len;
} curlString;

extern CURL* keyringCurl;

bool curlSetupSession(const char* url, const char* caFile, curlString* outStr);

#endif //KEYRING_CURL_H
