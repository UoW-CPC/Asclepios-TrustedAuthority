// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "aes_ccm.h"
#include <string.h>
#include "log.h"

EncryptorCCM::EncryptorCCM()
{
    unsigned char iv[AES_IV_SIZE] ={0x9F,0x62,0x54,0x4C,0x9D,0x3F,0xCA,0xB2};
    memcpy(m_original_iv, iv, AES_IV_SIZE);
}

int EncryptorCCM::initialize( unsigned char*key )
{
    int ret = 0;
    TRACE_ENCLAVE("ecall_dispatcher::initialize");

    memset((void*)m_encryption_key, 0, ENCRYPTION_KEY_SIZE_IN_BYTES);
    
    TRACE_ENCLAVE("copy encryption key");
 
    memcpy(m_encryption_key,key,ENCRYPTION_KEY_SIZE_IN_BYTES);

    // initialize aes context
    mbedtls_ccm_init( &m_aescontext );
    ret = mbedtls_ccm_setkey( &m_aescontext, MBEDTLS_CIPHER_ID_AES, m_encryption_key , ENCRYPTION_KEY_SIZE );

    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, AES_IV_SIZE);
exit:
    return ret;
}

int EncryptorCCM::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char** output_buf,
    size_t size,
    size_t *out_data_len)
{
    unsigned char output[ENCRYPTION_KEY_SIZE] = {0};
    // allocated memory (1)
    unsigned char* output_data = (unsigned char*)oe_host_malloc(ENCRYPTION_KEY_SIZE_IN_BYTES+TAG_LEN);
    //unsigned char* output_data;
    int ret = 0;

    if(encrypt==MBEDTLS_AES_ENCRYPT){
	/*
	unsigned char iv[]={0x9F,0x62,0x54,0x4C,0x9D,0x3F,0xCA,0xB2};
    	const char*msg="hello";
    	size_t msg_len = 5;
    	unsigned char key[] = { 0xD8,0xCC,0xAA,0x75 ,0x3E,0x29,0x83,0xF0 ,0x36,0x57,0xAB,0x3C ,0x8A,0x68,0xA8,0x5A};

    	mbedtls_ccm_context ctx;
    	mbedtls_ccm_init( &ctx );
    	mbedtls_ccm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, key, 8 * sizeof key );

    	unsigned char ciphertext[ENCRYPTION_KEY_SIZE+TAG_LEN];
	ret = mbedtls_ccm_encrypt_and_tag( &m_aescontext, size,
                     m_operating_iv, AES_IV_SIZE,NULL, 0,
                     (const unsigned char*)input_buf, ciphertext,
                     ciphertext+size, TAG_LEN );
	*/
	// allocated memory (1)
	//output_data = (unsigned char*)oe_host_malloc(ENCRYPTION_KEY_SIZE_IN_BYTES+TAG_LEN);
    	ret = mbedtls_ccm_encrypt_and_tag(&m_aescontext, size, 
			m_operating_iv, AES_IV_SIZE,
                        NULL, 0, 
			(const unsigned char*)input_buf, output_data, 
			output_data + size,TAG_LEN);
	
	 memcpy(m_operating_iv, m_original_iv, AES_IV_SIZE);
	 /*ret = mbedtls_ccm_auth_decrypt( &m_aescontext, size,
                                m_operating_iv, AES_IV_SIZE,
                                NULL, 0,
                                (const unsigned char*)ciphertext, output_data,
                                ciphertext + size, TAG_LEN );
	memcpy(m_operating_iv, m_original_iv, AES_IV_SIZE);*/
	if (ret != 0)
        {
                TRACE_ENCLAVE("mbedtls_ccm_encrypt_and_tag failed with %d", ret);
        } else {
                *output_buf = output_data;
	        *out_data_len = size + TAG_LEN;
	}
    } else { //decryption
	size_t msg_len = size - TAG_LEN; //the ciphertext string contains ciphertext content plus tag. Therefore, the length of ciphertext is equal to the size of the string subtracted TAG_LEN 
	// allocated memory (2) : output_data is allocated inside the decryption function
	ret = mbedtls_ccm_auth_decrypt( &m_aescontext, msg_len,
                                m_operating_iv, AES_IV_SIZE, 
				NULL, 0,
                                (const unsigned char*)input_buf, output_data,
                                input_buf + msg_len, TAG_LEN );
        memcpy(m_operating_iv, m_original_iv, AES_IV_SIZE);
	if (ret != 0)
        {
                TRACE_ENCLAVE("mbedtls_ccm_auth_decrypt failed with %d", ret);
        } else {
		*output_buf = output_data;
		*out_data_len = msg_len;
        }
    }
    return 1;
}

void EncryptorCCM::close()
{
    // free aes context
    mbedtls_ccm_free(&m_aescontext);

    //not implemented: free memory allocated (1,2)
    TRACE_ENCLAVE("encryptor::close");
}
