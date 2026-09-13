/*
 * zdecrypt - Decryptor for Zyxel "_encryp1_" JSON encoded fields
 *
 * Copyright © 2026 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef _MSC_VER
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <windows.h>
#else
#include <libgen.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <json-c/json.h>

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#ifndef APP_VERSION
#define APP_VERSION_STR "[DEV]"
#else
#define APP_VERSION_STR STRINGIFY(APP_VERSION)
#endif

// Maximum number of fields we can decrypt
#define MAX_FIELDS 1024

typedef struct {
	char* prefix;
	char* name;
	char* value;
} field_t;

field_t* fields = NULL;
int field_index = 0;

#ifdef _MSC_VER
static __inline char* basename(const char* path)
{
	static char basename[128];
	_splitpath_s(path, NULL, 0, NULL, 0, basename, sizeof(basename), NULL, 0);
	return basename;
}
#endif

char* base64_encode(const char* input, int* len)
{
	int input_len = *len;
	*len = 4 * ((input_len + 2) / 3) + 1;
	char* output = (char*)calloc(1, *len);
	EVP_EncodeBlock(output, input, input_len);
	return output;
}

char* base64_decode(const char* input, int* len)
{
	int input_len = *len;
	*len = ((int)strlen(input) / 4) * 3 + 1;
	char* output = (char*)calloc(1, *len);
	EVP_DecodeBlock(output, input, input_len);
	return output;
}

int aes_init(EVP_CIPHER_CTX* ctx, uint8_t* key_data, int key_data_len, uint8_t* salt)
{
	int len;
	uint8_t key[32], iv[32];

	len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, 5, key, iv);
	if (len != 0x20) {
		fprintf(stderr, "Key size is %d bits - should be 256 bits\n", len * 8);
		return -1;
	}
	if (ctx != NULL) {
		EVP_CIPHER_CTX_reset(ctx);
		EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	}
	return 0;
}

uint8_t* aes_decrypt(EVP_CIPHER_CTX* ctx, uint8_t* input, int* len)
{
	uint8_t* decrypted;
	int len2 = 0;

	decrypted = calloc(1, (*len + 0x21));
	if (decrypted != NULL) {
		EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
		EVP_DecryptUpdate(ctx, decrypted, len, input, *len);
		EVP_DecryptFinal_ex(ctx, &decrypted[*len], &len2);
		*len += len2;
	}
	return decrypted;
}

char* aes_decrypt_cbc_256(const char* input, char* keystr, int* len)
{
	const uint64_t salt = 0xd43100003039;
	char* ret = NULL;

	*len = (int)strlen(input);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (ctx != NULL && aes_init(ctx, keystr, (int)strlen(keystr), (uint8_t*)&salt) == 0) {
		char* decoded = base64_decode(input, len);
		if (decoded != NULL) {
			ret = aes_decrypt(ctx, decoded, len);
			free(decoded);
		}
	}
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

void digest_message(uint8_t* input, size_t input_len, uint8_t* digest)
{
	int len = EVP_MD_get_size(EVP_sha256());
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, input, input_len);
	EVP_DigestFinal_ex(ctx, digest, &len);
	EVP_MD_CTX_free(ctx);
}

// Recursively process the JSON elements and construct a Zyxel-style path as we move along
void json_process(json_object* jobj, const char* prefix, const char* name) {
	json_type type = json_object_get_type(jobj);

	if (type == json_type_object) {
		json_object_object_foreach(jobj, key, val) {
			char newprefix[1024];
			if (prefix[0] == '\0')
				snprintf(newprefix, sizeof(newprefix), "%s", name);
			else
				snprintf(newprefix, sizeof(newprefix), "%s.%s", prefix, name);
			json_process(val, newprefix, key);
		}
	} else if (type == json_type_array) {
		size_t len = json_object_array_length(jobj);
		for (size_t i = 0; i < len; i++) {
			json_object* item = json_object_array_get_idx(jobj, i);
			char newprefix[1024];
			snprintf(newprefix, sizeof(newprefix), "%s.%s", prefix, name);
			json_process(item, newprefix, "i");
		}
	} else if (type == json_type_string) {
		const char* val = json_object_get_string(jobj);
		if (val != NULL && strncmp(val, "_encryp1_", 9) == 0) {
			if (field_index < MAX_FIELDS) {
				fields[field_index].prefix = strdup(prefix);
				fields[field_index].name = strdup(name);
				fields[field_index++].value = strdup(&val[9]);
			}

		}
	}
}

int json_decrypt(const char* path)
{
	const char* zyxel_l33t = "2yX!";
	const char* data_autoconfig = "/dataAutoConfig320970";
	char encrypted[1024], *decrypted;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	bool found = false;

	fields = calloc(sizeof(field_t), MAX_FIELDS);
	json_object* backup = json_object_from_file(path);
	json_process(backup, "", "Device");
	json_object_put(backup);

	// Search for the base decryption key
	// The decryption key is basically base64(sha256sum(<16-bit value>)), with some
	// "2yX!" ("ZyXl" in l33t speak) sequences replacing characters [4-7] and [15-18],
	// and with the NUL terminated string "/dataAutoConfig320970" inserted at position 18.
	for (uint32_t base = 0x0000; base < 0x10000 && !found; base++) {
		printf("Trying derivation 0x%04x...\r", (uint16_t)base);
		fflush(stdout);
		bool garbage = false;
		// NB: This only works if compiled for little endian!
		digest_message((uint8_t*)&base, 2, digest);
		// For base == 0x000 the following results in base_key = "lqKW2yX!hcZ77pP2yX/dataAutoConfig320970"
		int len = sizeof(digest);
		char* base_key = base64_encode(digest, &len);
		memcpy(&base_key[4], zyxel_l33t, 4);
		memcpy(&base_key[15], zyxel_l33t, 4);
		strcpy(&base_key[18], data_autoconfig);
		for (int i = 0; i < field_index && !garbage; i++) {
			int j, len;
			// The actual key used for AES is the base_key concatenated with the path of the JSON parent
			// (e.g. "Device.X_ZYXEL_RESET_ADMIN" or "Device.X_ZYXEL_LoginCfg.LogGp.i") and the JSON field
			// name (e.g. "ResetPassword" or "GP_Privilege").
			// Note that, so that they encrypt and decrypt the same, array entries have their index set to
			// ".i" instead of ".0", ".1", etc.
			snprintf(encrypted, sizeof(encrypted), "%s%s%s", base_key, fields[i].prefix, fields[i].name);
			decrypted = aes_decrypt_cbc_256(fields[i].value, encrypted, &len);
			// Check if what we just decrypted looks like a readable ASCII string
			for (j = 0; j < len && decrypted[j] >= ' ' && decrypted[j] <= '~'; j++);
			garbage = (j == 0 || (j < len && decrypted[j] != '\0'));
			free(decrypted);
		}
		if (garbage) {
			// Got decrypted garbage => Try the next base value
			free(base_key);
			continue;
		}

		printf("Key prefix '%s' found at derivation 0x%04x.\n\n", base_key, (uint16_t)base);
		for (int i = 0; i < field_index; i++) {
			int len;
			snprintf(encrypted, sizeof(encrypted), "%s%s%s", base_key, fields[i].prefix, fields[i].name);
			decrypted = aes_decrypt_cbc_256(fields[i].value, encrypted, &len);
			printf("%s.%s['_encryp1_%s'] => '%s'\n", fields[i].prefix, fields[i].name, fields[i].value, decrypted);
			free(decrypted);
		}
		free(base_key);
		found = true;
	}

	if (!found) {
		printf("Unable to guess the key!   \n");
		printf("Please visit https://github.com/pbatard/zdecrypt#help-it-doesnt-work-for-me.\n");
	}

	for (int i = 0; i < field_index; i++) {
		free(fields[i].prefix);
		free(fields[i].name);
		free(fields[i].value);
	}
	free(fields);

	return 0;
}

#ifdef _MSC_VER
int main_utf8(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
	fprintf(stderr, "%s %s © 2026 Pete Batard <pete@akeo.ie>\n\n", basename(argv[0]), APP_VERSION_STR);
	fprintf(stderr, "This program is free software; you can redistribute it and/or modify it under \n");
	fprintf(stderr, "the terms of the GNU General Public License as published by the Free Software \n");
	fprintf(stderr, "Foundation; either version 3 of the License or any later version.\n\n");
	fprintf(stderr, "Official project and latest downloads at https://github.com/pbatard/zdecrypt.\n\n");

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <JSON file>\n\n", basename(argv[0]));
		return 1;
	}

	json_decrypt(argv[1]);
	OPENSSL_cleanup();
	return 0;
}

#ifdef _MSC_VER
static __inline char* wchar_to_utf8(const wchar_t* wstr)
{
	int size = 0;
	char* str = NULL;

	if (wstr[0] == 0)
		return (char*)calloc(1, 1);

	size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
	if (size <= 1)
		return NULL;

	if ((str = (char*)calloc(size, 1)) == NULL)
		return NULL;
	if (WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, size, NULL, NULL) != size) {
		free(str);
		return NULL;
	}

	return str;
}

int wmain(int argc, wchar_t** argv16)
{
	SetConsoleOutputCP(CP_UTF8);
	char** argv = calloc(argc, sizeof(char*));
	if (argv == NULL)
		return -1;
	for (int i = 0; i < argc; i++)
		argv[i] = wchar_to_utf8(argv16[i]);
	int r = main_utf8(argc, argv);
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif
	return r;
}
#endif
