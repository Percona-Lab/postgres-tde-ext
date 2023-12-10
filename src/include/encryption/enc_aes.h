/*-------------------------------------------------------------------------
 *
 * end_aes.h
 *	  AES Encryption / Decryption routines using OpenSSL
 *
 * src/include/encryption/enc_aes.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENC_AES_H
#define ENC_AES_H

#include <stdint.h>
#include "access/pg_tde_tdemap.h"
#include "keyring/keyring_api.h"

#define AES_BLOCK_SIZE 		        16
#define NUM_AES_BLOCKS_IN_BATCH     100
#define DATA_BYTES_PER_AES_BATCH    (NUM_AES_BLOCKS_IN_BATCH * AES_BLOCK_SIZE)

void AesInit(void);
extern void Aes128EncryptedZeroBlocks(void* ctxPtr, const unsigned char* key, uint64_t blockNumber1, uint64_t blockNumber2, unsigned char* out);

/* Only used for testing */
extern void AesEncrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len);
extern void AesDecrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len);

extern void AesEncryptKey(const keyInfo *master_key_info, RelKeysData *rel_key_data, RelKeysData **p_enc_rel_key_data, size_t *enc_key_bytes);
extern void AesDecryptKey(const keyInfo *master_key_info, RelKeysData **p_rel_key_data, RelKeysData *enc_rel_key_data, size_t *key_bytes);

#endif /*ENC_AES_H*/