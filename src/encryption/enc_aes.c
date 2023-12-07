
#ifndef FRONTEND
#include "postgres.h"
#else
#include <assert.h>
#define Assert(p) assert(p)
#endif

#include "utils/memutils.h"

#include "access/pg_tde_tdemap.h"
#include "encryption/enc_aes.h"
#include "keyring/keyring_api.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Implementation notes
 * =====================
 *
 * AES-CTR in a nutshell:
 * * Uses a counter, 0 for the first block, 1 for the next block, ...
 * * Encrypts the counter using AES-ECB
 * * XORs the data to the encrypted counter
 *
 * In our implementation, we want random access into any 16 byte part of the encrypted datafile.
 * This is doable with OpenSSL and directly using AES-CTR, by passing the offset in the correct format as IV.
 * Unfortunately this requires reinitializing the OpenSSL context for every seek, and that's a costly operation.
 * Initialization and then decryption of 8192 bytes takes just double the time of initialization and deecryption
 * of 16 bytes.
 *
 * To mitigate this, we reimplement AES-CTR using AES-ECB:
 * * We only initialize one ECB context per encryption key (e.g. table), and store this context
 * * When a new block is requested, we use this stored context to encrypt the position information
 * * And then XOR it with the data
 *
 * This is still not as fast as using 8k blocks, but already 2 orders of magnitude better than direct CTR with 
 * 16 byte blocks.
 */

/* 
 * Let's have a single definition of the IV across the code. SET_IV should
 * be at the end of a variable declaration block. If not, a compilation
 * warning will be generated informing of nonconformance ISO C90 due to
 * mixing of declarations and code.
 */
typedef unsigned char TDE_iv[INTERNAL_KEY_LEN];
#define SET_IV(iv)                                      \
            TDE_iv iv;                                  \
            memset((void *)iv, 0x00, sizeof(TDE_iv));


const EVP_CIPHER* cipher = NULL;
const EVP_CIPHER* cipher2 = NULL;
int cipher_block_size = 0;

void AesInit(void)
{
	static int initialized = 0;

	if(!initialized) {
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();
	
		cipher = EVP_aes_128_cbc();
		cipher_block_size = EVP_CIPHER_block_size(cipher); // == buffer size
		cipher2 = EVP_aes_128_ecb();

		initialized = 1;
	}
}

// TODO: a few things could be optimized in this. It's good enough for a prototype.
static void
AesRun2(EVP_CIPHER_CTX** ctxPtr, int enc, const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len)
{
	if (*ctxPtr == NULL)
	{
		*ctxPtr = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(*ctxPtr);
		
		EVP_CIPHER_CTX_set_padding(*ctxPtr, 0);

		if(EVP_CipherInit_ex(*ctxPtr, cipher2, NULL, key, iv, enc) == 0)
		{
			#ifdef FRONTEND
				fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			#else
				ereport(ERROR,
					(errmsg("EVP_CipherInit_ex failed. OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))));
			#endif

			return;
		}
	}

	if(EVP_CipherUpdate(*ctxPtr, out, out_len, in, in_len) == 0)
	{
		#ifdef FRONTEND
			fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		#else
			ereport(ERROR,
				(errmsg("EVP_CipherUpdate failed. OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))));
		#endif
		return;
	}
}

static void AesRun(int enc, const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len)
{
	EVP_CIPHER_CTX* ctx = NULL;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc) == 0)
	{
		#ifdef FRONTEND
			fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		#else
			ereport(ERROR,
				(errmsg("EVP_CipherInit_ex failed. OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))));
		#endif
		goto cleanup;
	}

	if(EVP_CipherUpdate(ctx, out, out_len, in, in_len) == 0)
	{
		#ifdef FRONTEND
			fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		#else
			ereport(ERROR,
				(errmsg("EVP_CipherUpdate failed. OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))));
		#endif
		goto cleanup;
	}

	if(EVP_CipherFinal_ex(ctx, out, out_len) == 0)
	{
		#ifdef FRONTEND
			fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		#else
			ereport(ERROR,
				(errmsg("EVP_CipherFinal_ex failed. OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL))));
		#endif
		goto cleanup;
	}

cleanup:
 	EVP_CIPHER_CTX_cleanup(ctx);
 	EVP_CIPHER_CTX_free(ctx);
}

void AesEncrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len)
{
	AesRun(1, key, iv, in, in_len, out, out_len);
}

void
AesEncryptKey(const keyInfo *master_key_info, RelKeysData *rel_key_data, RelKeysData *enc_rel_key_data, size_t *enc_key_bytes)
{
	size_t sz;
	SET_IV(iv);

	/* Ensure we are getting a valid pointer here */
	Assert(master_key_info);

	sz = SizeOfRelKeysData(rel_key_data->internal_keys_len);

	enc_rel_key_data = (RelKeysData *) palloc(SizeOfRelKeysData(1));
	memcpy(enc_rel_key_data, rel_key_data, sz);

	AesEncrypt(master_key_info->data.data, iv, (unsigned char*)rel_key_data + SizeOfRelKeysDataHeader, INTERNAL_KEY_LEN, (unsigned char *)enc_rel_key_data + SizeOfRelKeysDataHeader, (int *)enc_key_bytes);
}

void AesDecrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* in, int in_len, unsigned char* out, int* out_len)
{
	AesRun(0, key, iv, in, in_len, out, out_len);
}

void
AesDecryptKey(const keyInfo *master_key_info, RelKeysData *rel_key_data, RelKeysData *enc_rel_key_data, size_t *key_bytes)
{
	size_t sz;
	SET_IV(iv);

	/* Ensure we are getting a valid pointer here */
	Assert(master_key_info);

	sz = SizeOfRelKeysData(enc_rel_key_data->internal_keys_len);

	rel_key_data = (RelKeysData *) MemoryContextAlloc(TopMemoryContext, sz);

	/* Fill in the structure */
	memcpy(rel_key_data, enc_rel_key_data, sz);

	AesDecrypt(master_key_info->data.data, iv, (unsigned char*) enc_rel_key_data->internal_key, INTERNAL_KEY_LEN, (unsigned char *)enc_rel_key_data->internal_key, (int *)key_bytes);
}

/*
 * We want to avoid dynamic memory allocation, so the function only allows
 * to process NUM_AES_BLOCKS_IN_BATCH number of blocks at a time.
 * If the caller wants to process more than NUM_AES_BLOCKS_IN_BATCH * AES_BLOCK_SIZE
 * data it should divide the data into batches and call this function for each batch.
 */
void Aes128EncryptedZeroBlocks(void* ctxPtr, const unsigned char* key, uint64_t blockNumber1, uint64_t blockNumber2, unsigned char* out)
{
	int index;
	unsigned dataLen = (blockNumber2 - blockNumber1) * INTERNAL_KEY_LEN;
	unsigned char data[DATA_BYTES_PER_AES_BATCH];
	int outLen;
	SET_IV(iv);

	Assert(blockNumber2 >= blockNumber1);
	Assert(dataLen <= DATA_BYTES_PER_AES_BATCH);

	memset(data, 0, dataLen);
	for(int j=blockNumber1;j<blockNumber2;++j)
	{
		for(int i =0; i<8;++i)
		{
			index = INTERNAL_KEY_LEN * (j - blockNumber1) + (INTERNAL_KEY_LEN - 1) - i;
			data[index] = (j >> (8*i)) & 0xFF;
		}
	}

	AesRun2(ctxPtr, 1, key, iv, data, dataLen, out, &outLen);
	Assert(outLen == dataLen);
}
