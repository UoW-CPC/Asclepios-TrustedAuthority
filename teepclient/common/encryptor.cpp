// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "log.h"

Encryptor::Encryptor() : m_encrypt(true)
{
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);
}

int Encryptor::initialize( bool encrypt, unsigned char*key )
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    m_encrypt = encrypt;
    memset((void*)m_encryption_key, 0, ENCRYPTION_KEY_SIZE_IN_BYTES);
    
    TRACE_ENCLAVE("copy encryption key");
 
    memcpy(m_encryption_key,key, ENCRYPTION_KEY_SIZE_IN_BYTES);

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);

    // set aes key
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);

    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return ret;
}

int Encryptor::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char** output_buf,
    size_t size,
    size_t *out_data_len)
{
    unsigned char output[128] = {0};
    unsigned char output2[128] = {0};

    mbedtls_aes_crypt_cbc( &m_aescontext, MBEDTLS_AES_ENCRYPT, strlen((const char*)input_buf), m_operating_iv, input_buf, output );
    memcpy(m_operating_iv,m_original_iv,IV_SIZE);
   
    //decryption - test only 
    mbedtls_aes_setkey_dec( &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE );
    mbedtls_aes_crypt_cbc( &m_aescontext, MBEDTLS_AES_DECRYPT, strlen((const char*)output), m_operating_iv, output, output2 );


    unsigned char* output_data = (unsigned char*)oe_host_malloc(16);
    memcpy(output_data,output2,strlen((const char*)output2));
    *output_buf = output_data;
    *out_data_len = (int)strlen((const char*)output2);

    return 1;
}

void Encryptor::close()
{
    // free aes context
    mbedtls_aes_free(&m_aescontext);
    TRACE_ENCLAVE("encryptor::close");
}
