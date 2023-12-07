/*-------------------------------------------------------------------------
 *
 * pg_tde_tdemap.c
 *	  tde relation fork manager code
 *
 *
 * IDENTIFICATION
 *	  src/access/pg_tde_tdemap.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "access/pg_tde_tdemap.h"
#include "transam/pg_tde_xact_handler.h"
#include "storage/fd.h"
#include "utils/wait_event.h"
#include "utils/memutils.h"
#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "access/xloginsert.h"

#include "access/pg_tde_tdemap.h"
#include "encryption/enc_aes.h"
#include "keyring/keyring_api.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

#include "pg_tde_defines.h"


#define PG_TDE_MAP_FILENAME			"pg_tde.map"
#define PG_TDE_KEYDATA_FILENAME		"pg_tde.dat"

static char *db_path = NULL;
static char *db_map_path = NULL;
static char *db_keydata_path = NULL;

/* TODO: should be a user defined */
static const char *MasterKeyName = "master-key";

static void put_keys_into_map(Oid rel_id, RelKeysData *keys);
static void pg_tde_xlog_create_fork(XLogReaderState *record);

static void pg_tde_create_key_map_entry(const RelFileLocator *rlocator, InternalKey *key, const char *master_key_name);
static RelKeysData* pg_tde_get_key_from_file(const RelFileLocator *rlocator, const char *master_key_name);
static RelKeysData* tde_create_rel_key(const RelFileLocator *rlocator, InternalKey *key, const keyInfo *master_key_info);
static RelKeysData* tde_encrypt_rel_key(const keyInfo *master_key_info, RelKeysData *rel_key_data);
static RelKeysData* tde_decrypt_rel_key(const keyInfo *master_key_info, RelKeysData *enc_rel_key_data);
static void pg_tde_set_db_file_paths(const RelFileLocator *rlocator);
static void pg_tde_cleanup_path_vars(void);
static File pg_tde_open_file(char *tde_filename, const char *master_key_name, int fileFlags, bool *is_new_file);
static int32 pg_tde_write_map_entry(const RelFileLocator *rlocator, char *db_map_path, const char *master_key_name);
static int32 pg_tde_read_map_entry(const RelFileLocator *rlocator, char *db_map_path, const char *master_key_name);
static void pg_tde_write_keydata(char *db_keydata_path, const char *master_key_name, int32 key_index, RelKeysData *enc_rel_key_data);
static RelKeysData* pg_tde_read_keydata(char *db_keydata_path, int32 key_index, const char *master_key_name);

void
pg_tde_delete_key_fork(Relation rel)
{
	/* TODO: delete related internal keys from cache */
	// char    *key_file_path = pg_tde_get_key_file_path(&rel->rd_locator);
    // if (!key_file_path)
	// {
    //     ereport(ERROR,
    //             (errmsg("failed to get key file path")));
	// }
	// RegisterFileForDeletion(key_file_path, true);
	// pfree(key_file_path);
}

/*
 * Creates a relation fork file relfilenode.tde that contains the
 * encryption key for the relation.
 */
void
pg_tde_create_key_fork(const RelFileLocator *newrlocator, Relation rel)
{
	InternalKey int_key;

	memset(&int_key, 0, sizeof(InternalKey));

	if (!RAND_bytes(int_key.key, INTERNAL_KEY_LEN))
	{
		ereport(FATAL,
				(errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate internal key for relation \"%s\": %s",
                		RelationGetRelationName(rel), ERR_error_string(ERR_get_error(), NULL))));
	}


	/* XLOG internal keys */
	XLogBeginInsert();
	XLogRegisterData((char *) newrlocator, sizeof(RelFileLocator));
	XLogRegisterData((char *) &int_key, sizeof(InternalKey));
	XLogInsert(RM_TDERMGR_ID, XLOG_TDE_CREATE_FORK);

	/* TODO: should DB crash after sending XLog, secondaries would create a fork
	 * file but the relation won't be created either on primary or secondaries.
	 * Hence, the *.tde file will remain as garbage on secondaries.
	 */

	pg_tde_create_key_map_entry(newrlocator, &int_key, MasterKeyName);
}

/* Head of the keys cache (linked list) */
RelKeys *tde_rel_keys_map = NULL;

/*
 * Returns TDE keys for a given relation.
 * First it looks in a cache. If nothing found in the cache, it reads data from
 * the tde fork file and populates cache.
 */
RelKeysData *
GetRelationKeys(RelFileLocator rel)
{
	RelKeys		*curr;
	RelKeysData *keys;

	Oid rel_id = rel.relNumber;
	for (curr = tde_rel_keys_map; curr != NULL; curr = curr->next)
	{
		if (curr->rel_id == rel_id)
		{
			return curr->keys;
		}
	}

	keys = pg_tde_get_key_from_file(&rel, MasterKeyName);

	put_keys_into_map(rel.relNumber, keys);

	return keys;
}

static void
put_keys_into_map(Oid rel_id, RelKeysData *keys) {
	RelKeys		*new;
	RelKeys		*prev = NULL;

	new = (RelKeys *) MemoryContextAlloc(TopMemoryContext, sizeof(RelKeys));
	new->rel_id = rel_id;
	new->keys = keys;
	new->next = NULL; 

	if (prev == NULL)
		tde_rel_keys_map = new;
	else
		prev->next = new;
}

const char *
tde_sprint_key(InternalKey *k)
{
	static char buf[256];
	int 	i;

	for (i = 0; i < sizeof(k->key); i++)
		sprintf(buf+i, "%02X", k->key[i]);

	sprintf(buf+i, "[%lu, %lu]", k->start_loc, k->end_loc);

	return buf;
}

const char *
tde_sprint_masterkey(const keyData *k)
{
	static char buf[256];
	int 	i;

	for (i = 0; i < k->len; i++)
		sprintf(buf+i, "%02X", k->data[i]);

	return buf;
}

RelKeysData *
tde_create_rel_key(const RelFileLocator *rlocator, InternalKey *key, const keyInfo *master_key_info)
{
	RelKeysData 	*rel_key_data;

	rel_key_data = (RelKeysData *) MemoryContextAlloc(TopMemoryContext, SizeOfRelKeysData(1));

	strcpy(rel_key_data->master_key_name, master_key_info->name.name);
	rel_key_data->internal_key[0] = *key;
	rel_key_data->internal_keys_len = 1;

	/* Add to the cache */
	put_keys_into_map(rlocator->relNumber, rel_key_data);

	return rel_key_data;
}

RelKeysData *
tde_encrypt_rel_key(const keyInfo *master_key_info, RelKeysData *rel_key_data)
{
	RelKeysData *enc_rel_key_data = NULL;
	size_t enc_key_bytes;

	AesEncryptKey(master_key_info, rel_key_data, enc_rel_key_data, &enc_key_bytes);

	return enc_rel_key_data;
}

RelKeysData *
tde_decrypt_rel_key(const keyInfo *master_key_info, RelKeysData *enc_rel_key_data)
{
	RelKeysData *rel_key_data = NULL;
	size_t key_bytes;

	AesDecryptKey(master_key_info, rel_key_data, enc_rel_key_data, &key_bytes);

	return rel_key_data;
}

/*
 * Sets the global variables so that we don't have to do this again for this
 * backend lifetime.
 */
void
pg_tde_set_db_file_paths(const RelFileLocator *rlocator)
{
	/* Return if the values are already set */
	if (db_path && db_map_path && db_keydata_path)
		return;

	/* Fill in the values */
	db_path = GetDatabasePath(rlocator->dbOid, rlocator->spcOid);
	db_map_path = psprintf("%s/%s", db_path, PG_TDE_MAP_FILENAME);
	db_keydata_path = psprintf("%s/%s", db_path, PG_TDE_KEYDATA_FILENAME);
}

/*
 * Path data clean up once the transaction is done.
 */
void
pg_tde_cleanup_path_vars(void)
{
#define pfree_and_set_null(p)	if (p) pfree(p); p = NULL;

	pfree_and_set_null(db_path);
	pfree_and_set_null(db_map_path);
	pfree_and_set_null(db_keydata_path);
}


#define PG_TDE_FILEMAGIC				0x54444501	/* version ID value = TDE 01 */

#define MAP_ENTRY_FREE					0x00
#define MAP_ENTRY_VALID					0x01

#define MAP_ENTRY_SIZE					sizeof(TDEMapEntry)
#define TDE_FILE_HEADER_SIZE			sizeof(TDEFileHeader)

typedef struct TDEFileHeader
{
	int32 file_version;
	char master_key_name[MASTER_KEY_NAME_LEN];
} TDEFileHeader;

typedef struct TDEMapEntry
{
	RelFileNumber relNumber;
	int32 flags;
	int32 key_index;
} TDEMapEntry;

/*
 * Open and Validate File Header [pg_tde.*]:
 * 		header: {Format Version, Master Key Name}
 * 
 * Returns the file descriptor in case of a success. Otherwise, fatal error
 * is raised.
 * 
 * Also, it sets the is_new_file to true if the file is just created. This is
 * useful to know when reading a file so that we can skip further processing.
 * 
 * Plus, there is nothing wrong with a create even if we are going to read
 * data. This will save the creation overhead the next time. Ideally, this
 * should never happen for a read operation as it indicates a missing file.
 * 
 * The caller can pass the required flags to ensure that file is created
 * or an error is thrown if the file does not exist.
 */
File
pg_tde_open_file(char *tde_filename, const char *master_key_name, int fileFlags, bool *is_new_file)
{
	File tde_file = -1;
	TDEFileHeader fheader;
	int bytes_read = 0;

	/*
	 * Ensuring that we always open the file in binary mode. The caller must
	 * specify other flags for reading, writing or creating the file.
	 */
	tde_file = PathNameOpenFile(tde_filename, fileFlags | PG_BINARY);
	if (tde_file < 0)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
				 errmsg("Could not open tde file \"%s\": %m",
						tde_filename)));
	}

	bytes_read = FileRead(tde_file, &fheader, TDE_FILE_HEADER_SIZE, 0, WAIT_EVENT_DATA_FILE_READ);
	*is_new_file = (bytes_read == 0);

	/* File doesn't exist */
	if (bytes_read == 0)
	{
		/* Create the header for this file. */
		fheader.file_version = PG_TDE_FILEMAGIC;
		memcpy(fheader.master_key_name, master_key_name, MASTER_KEY_NAME_LEN);

		if (FileWrite(tde_file, &fheader, TDE_FILE_HEADER_SIZE, 0, WAIT_EVENT_DATA_FILE_WRITE) != TDE_FILE_HEADER_SIZE)
		{
			ereport(FATAL,
					(errcode_for_file_access(),
					 errmsg("Could not write tde file \"%s\": %m",
							tde_filename)));
		}
	}
	else if (bytes_read != TDE_FILE_HEADER_SIZE
			|| fheader.file_version != PG_TDE_FILEMAGIC
			|| memcmp(fheader.master_key_name, master_key_name, MASTER_KEY_NAME_LEN) != 0)
	{
		/* Corrupt file */
		ereport(FATAL,
				(errcode_for_file_access(),
				 errmsg("File \"%s\" is corrupted or the master key name is not valid: %m",
					tde_filename)));
	}

	return tde_file;
}

/*
 * Key Map Table [pg_tde.map]:
 * 		header: {Format Version, Master Key Name}
 * 		data: {OID, Flag, index of key in pg_tde.dat}...
 * 
 * Returns the index of the key to be written in the key data file.
 * The caller must hold an exclusive lock on the map file to avoid
 * concurrent in place updates leading to data conflicts.
 */
int32
pg_tde_write_map_entry(const RelFileLocator *rlocator, char *db_map_path, const char *master_key_name)
{
	File map_file = -1;
	int32 key_index = 0;
	TDEMapEntry map_entry;
	bool is_new_file;

	/* Open and vaidate file for basic correctness. */
	map_file = pg_tde_open_file(db_map_path, master_key_name, O_RDWR | O_CREAT, &is_new_file);

	/*
	 * Read until we find an empty slot. Otherwise, read until end. This seems
	 * to be less frequent than vacuum. So let's keep this function here rather
	 * than overloading the vacuum process.
	 */
	while(FileRead(map_file, &map_entry, MAP_ENTRY_SIZE, 0, WAIT_EVENT_DATA_FILE_READ))
	{
		/* We found an empty slot */
		if (map_entry.flags == MAP_ENTRY_FREE)
		{
			/* Let's seek back to the writing position */
			if (lseek(map_file, MAP_ENTRY_SIZE * -1, SEEK_CUR) == -1)
			{
				ereport(FATAL,
						(errcode_for_file_access(),
						 errmsg("lseek failed for \"%s\": %m",
							db_map_path)));
			}

			break;
		}

		/* Increment the key index only if we didn't get an empty slot. */
		key_index++;
	}

	/* Fill in the map entry structure */
	map_entry.relNumber = rlocator->relNumber;
	map_entry.flags = MAP_ENTRY_VALID;
	map_entry.key_index = key_index;

	/* Add the entry to the file */
	if (FileWrite(map_file, &map_entry, MAP_ENTRY_SIZE, 0, WAIT_EVENT_DATA_FILE_WRITE) != MAP_ENTRY_SIZE)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
					errmsg("Could not write tde map file \"%s\": %m",
						db_map_path)));
	}

	/* Let's close the file. */
	FileClose(map_file);

	return key_index;
}

int32
pg_tde_read_map_entry(const RelFileLocator *rlocator, char *db_map_path, const char *master_key_name)
{
	File map_file = -1;
	int32 key_index = 0;
	TDEMapEntry map_entry;
	bool is_new_file;
	bool found = false;

	/* Open and vaidate file for basic correctness. */
	map_file = pg_tde_open_file(db_map_path, master_key_name, O_RDONLY, &is_new_file);

	/*
	 * Read until we find an empty slot. Otherwise, read until end. This seems
	 * to be less frequent than vacuum. So let's keep this function here rather
	 * than overloading the vacuum process.
	 */
	while(FileRead(map_file, &map_entry, MAP_ENTRY_SIZE, 0, WAIT_EVENT_DATA_FILE_READ))
	{
		/* We found a valid entry for the relNumber */
		if (map_entry.flags == MAP_ENTRY_VALID && map_entry.relNumber == rlocator->relNumber)
		{
			found = true;
			break;
		}

		/* Increment the key index only if we didn't get a valid slot. */
		key_index++;
	}

	/* Let's close the file. */
	FileClose(map_file);

	/* An entry was expected but none was found */
	if (found == false)
	{
		ereport(FATAL,
				(errcode(ERRCODE_NO_DATA_FOUND),
					errmsg("Could not find the required entry for relNumber %d in tde map file \"%s\": %m",
						rlocator->relNumber,
						db_map_path)));
	}

	/* Return the index */
	return key_index;
}

/*
 * Key Data [pg_tde.dat]:
 * 		header: {Format Version: x}
 * 		data: {Encrypted Key}
 * 
 * Requires a valid index of the key to be written. The function with seek to
 * the required location in the file. Any holes will be filled when another
 * job finds an empty index.
 */
void
pg_tde_write_keydata(char *db_keydata_path, const char *master_key_name, int32 key_index, RelKeysData *enc_rel_key_data)
{
	File keydata_file = -1;
	off_t write_pos;
	bool is_new_file;
	size_t key_size;

	/* Open and vaidate file for basic correctness. */
	keydata_file = pg_tde_open_file(db_keydata_path, master_key_name, O_RDWR | O_CREAT, &is_new_file);

	/* Calculate the writing position in the file. */
	write_pos = TDE_FILE_HEADER_SIZE + (key_index * INTERNAL_KEY_LEN);

	if (lseek(keydata_file, write_pos, SEEK_SET) == -1)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
					errmsg("Could not seek in tde key data file \"%s\": %m",
						db_keydata_path)));
	}

	key_size = SizeOfRelKeysData(enc_rel_key_data->internal_keys_len);

	if (FileWrite(keydata_file, enc_rel_key_data, key_size, 0, WAIT_EVENT_DATA_FILE_WRITE) != key_size)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
					errmsg("Could not write tde key data file \"%s\": %m",
						db_keydata_path)));
	}

	/* Let's close the file. */
	FileClose(keydata_file);
}

/*
 * 
 */
RelKeysData *
pg_tde_read_keydata(char *db_keydata_path, int32 key_index, const char *master_key_name)
{
	File keydata_file = -1;
	RelKeysData *enc_rel_key_data;
	off_t read_pos;
	bool is_new_file;
	size_t key_size;
	size_t key_data_size;
	int key_count = 1;

	/* Open and vaidate file for basic correctness. */
	keydata_file = pg_tde_open_file(db_keydata_path, master_key_name, O_RDONLY, &is_new_file);

	/*
	 * Allocate in TopMemoryContext and don't pfree sice we add it to
	 * the cache as well
	 */
	key_size = SizeOfRelKeysData(key_count);
	key_data_size = key_size - SizeOfRelKeysDataHeader;

	/* Allocate and fill in the structure */
	enc_rel_key_data = (RelKeysData *) palloc(key_size);

	strcpy(enc_rel_key_data->master_key_name, master_key_name);
	enc_rel_key_data->internal_keys_len = key_count;

	/* Calculate the reading position in the file. */
	read_pos = TDE_FILE_HEADER_SIZE + (key_index * INTERNAL_KEY_LEN);

	/* Check if the file has a valid key */
	if ((read_pos + key_data_size) > FileSize(keydata_file))
	{
		ereport(FATAL,
				(errcode(ERRCODE_NO_DATA_FOUND),
					errmsg("Could not find the required key at index %d in tde data file \"%s\": %m",
						key_index,
						db_keydata_path)));
	}

	/* Seek to the key start */
	if (lseek(keydata_file, read_pos, SEEK_SET) == -1)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
					errmsg("Could not seek in tde key data file \"%s\": %m",
						db_keydata_path)));
	}

	/* Read the encrypted key */
	if (FileRead(keydata_file, enc_rel_key_data->internal_key, key_data_size, 0, WAIT_EVENT_DATA_FILE_READ) != key_data_size)
	{
		ereport(FATAL,
				(errcode_for_file_access(),
					errmsg("Could not read key at index %d in tde key data file \"%s\": %m",
						key_index,
						db_keydata_path)));
	}

	/* Let's close the file. */
	FileClose(keydata_file);

	return enc_rel_key_data;
}

/*
 * Calls the create map entry function to get an index into the keydata. This
 * The keydata function will then write the encrypted key on the desired
 * location.
 * 
 * The map file must be updated while holding an exclusive lock.
 */
void
pg_tde_create_key_map_entry(const RelFileLocator *rlocator, InternalKey *key, const char *master_key_name)
{
	int32 key_index = 0;
	const keyInfo *master_key_info;
	RelKeysData *rel_key_data;
	RelKeysData *enc_rel_key_data;

	/* Get/generate a master, create the key for relation and get the encrypted key with bytes to write */
	master_key_info = getMasterKey(master_key_name, true, true);

	rel_key_data = tde_create_rel_key(rlocator, key, master_key_info);
	enc_rel_key_data = tde_encrypt_rel_key(master_key_info, rel_key_data);

	/* Get the file paths */
	pg_tde_set_db_file_paths(rlocator);

	/* Create the map entry and then add the encrypted key to the data file */
	key_index = pg_tde_write_map_entry(rlocator, db_map_path, master_key_name);

	/* Add the encrypted key to the data file. */
	pg_tde_write_keydata(db_keydata_path, master_key_name, key_index, enc_rel_key_data);
}

RelKeysData *
pg_tde_get_key_from_file(const RelFileLocator *rlocator, const char *master_key_name)
{
	int32 key_index = 0;
	const keyInfo *master_key_info;
	RelKeysData *rel_key_data;
	RelKeysData *enc_rel_key_data;

	/* Get/generate a master, create the key for relation and get the encrypted key with bytes to write */
	master_key_info = getMasterKey(master_key_name, true, true);

	/* Get the file paths */
	pg_tde_set_db_file_paths(rlocator);

	/* Create the map entry and then add the encrypted key to the data file */
	key_index = pg_tde_read_map_entry(rlocator, db_map_path, master_key_name);

	/* Add the encrypted key to the data file. */
	enc_rel_key_data = pg_tde_read_keydata(db_keydata_path, key_index, master_key_info->name.name);
	rel_key_data = tde_decrypt_rel_key(master_key_info, enc_rel_key_data);

	return rel_key_data;
}

/* 
 * TDE fork XLog 
 */
void
pg_tde_rmgr_redo(XLogReaderState *record)
{
	uint8	info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	switch (info)
	{
		case XLOG_TDE_CREATE_FORK:
			pg_tde_xlog_create_fork(record);
			break;
		default:
			elog(PANIC, "pg_tde_redo: unknown op code %u", info);
	}
}

void
pg_tde_rmgr_desc(StringInfo buf, XLogReaderState *record)
{
	uint8			info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;
	char			*rec = XLogRecGetData(record);
	RelFileLocator	rlocator;

	if (info == XLOG_TDE_CREATE_FORK)
	{
		memcpy(&rlocator, rec, sizeof(RelFileLocator));
		appendStringInfo(buf, "create tde fork for relation %u/%u", rlocator.dbOid, rlocator.relNumber);
	}
}

const char *
pg_tde_rmgr_identify(uint8 info)
{
	if ((info & ~XLR_INFO_MASK) == XLOG_TDE_CREATE_FORK)
		return "TDE_CREATE_FORK";

	return NULL;
}

static void
pg_tde_xlog_create_fork(XLogReaderState *record)
{
	char			*rec = XLogRecGetData(record);
	RelFileLocator	rlocator;
	InternalKey 	int_key;

	memset(&int_key, 0, sizeof(InternalKey));

	if (XLogRecGetDataLen(record) < sizeof(InternalKey)+sizeof(RelFileLocator))
	{
		ereport(FATAL,
				(errcode(ERRCODE_DATA_CORRUPTED),
				errmsg("corrupted XLOG_TDE_CREATE_FORK data")));
	}

	/* Format [RelFileLocator][InternalKey] */
	memcpy(&rlocator, rec, sizeof(RelFileLocator));
	memcpy(&int_key, rec+sizeof(RelFileLocator), sizeof(InternalKey));

#if TDE_FORK_DEBUG
	ereport(DEBUG2,
		(errmsg("xlog internal_key: %s", tde_sprint_key(&int_key))));
#endif

	pg_tde_create_key_map_entry(&rlocator, &int_key, MasterKeyName);	
}