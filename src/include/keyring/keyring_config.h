
#ifndef KEYRING_CONFIG_H
#define KEYRING_CONFIG_H

#include "postgres.h"

#include <json.h>

enum KeyringProvider
{
	PROVIDER_UNKNOWN,
	PROVIDER_FILE,
	PROVIDER_VAULT_V2,
} ;

extern enum KeyringProvider keyringProvider;
extern char* keyringConfigFile;
extern char* keyringKeyPrefix;

void keyringRegisterVariables(void);

bool keyringLoadConfiguration(const char* configFileName);


// If it's a hash, tries to retrieve the remote value
// { type: 'remote'. url: 'http://...' }
// If it doesn't have a type key / not remote / ... returns NULL
// Otherwise it retuns the JSON value interpreted as a string
bool keyringParseStringParam(const char* name, json_object* object, char* out, long outLen);

#endif // KEYRING_CONFIG_H
