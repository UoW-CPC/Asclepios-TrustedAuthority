// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>

using namespace std;

#define IV_SIZE 16
#define HASH_VALUE_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 128
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
class Encryptor
{
  private:
    mbedtls_aes_context m_aescontext;
    bool m_encrypt;
    string m_password;

    // initialization vector
    unsigned char m_original_iv[IV_SIZE];
    unsigned char m_operating_iv[IV_SIZE];

    // key for encrypting  data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

  public:
    Encryptor();
    int initialize(bool encrypt, unsigned char*key);
    int encrypt_block(
        bool encrypt,
        unsigned char* input_buf,
        unsigned char** output_buf,
        size_t size,
	size_t *out_data_len);
    void close();
   // int generate_encryption_key(unsigned char* key, unsigned int key_len);
  private:
    int generate_encryption_key(unsigned char* key, unsigned int key_len);
  /*  int generate_password_key(
        const char* password,
        unsigned char* key,
        unsigned int key_len);
    int generate_encryption_key(unsigned char* key, unsigned int key_len);
    int prepare_encryption_header(encryption_header_t* header, string password);
    int parse_encryption_header(encryption_header_t* header, string password);
    int cipher_encryption_key(
        bool encrypt,
        unsigned char* input_data,
        unsigned int input_data_size,
        unsigned char* encrypt_key,
        unsigned char* output_data,
        unsigned int output_data_size);
    int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);
    void dump_data(const char* name, unsigned char* data, size_t data_size);
    int process_encryption_header(
        bool encrypt,
        const char* password,
        size_t password_len,
        encryption_header_t* header);*/
};
