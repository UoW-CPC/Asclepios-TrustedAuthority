// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>

using namespace std;

#define AES_IV_SIZE 8 // bytes
#define HASH_VALUE_SIZE_IN_BYTES 32
#define ENCRYPTION_KEY_SIZE 128
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define TAG_LEN 8 
class EncryptorCCM
{
  private:
    //mbedtls_aes_context m_aescontext;
    mbedtls_ccm_context m_aescontext;

    // initialization vector
    unsigned char m_original_iv[AES_IV_SIZE];
    unsigned char m_operating_iv[AES_IV_SIZE];

    // key for encrypting  data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

  public:
    EncryptorCCM();
    int initialize(unsigned char*key);
    int encrypt_block(
        bool encrypt,
        unsigned char* input_buf,
        unsigned char** output_buf,
        size_t size,
	size_t *out_data_len);
    void close();
};
