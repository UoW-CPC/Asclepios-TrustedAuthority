// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"
#include "encryptor.h"

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t* enclave_secret_data;
    const char* other_enclave_pubkey_pem;
    size_t other_enclave_pubkey_pem_size;
} enclave_config_data_t;

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto; // RSA encryption
    Attestation* m_attestation;
    string m_name;
    enclave_config_data_t* m_enclave_config;
    unsigned char m_other_enclave_mrsigner[32];
    
    Encryptor* m_encryptor; //AES encryption
  public:
    ecall_dispatcher(const char* name, enclave_config_data_t* enclave_config);
    ~ecall_dispatcher();
    int get_remote_report_with_pubkey(
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size);
    int verify_report_and_set_pubkey(
        uint8_t* pem_key,
        size_t key_size,
        uint8_t* remote_report,
        size_t remote_report_size);
    int rsa_test(
        uint8_t* data, 
        size_t data_len);
     //void  retrieve_private_key(uint8_t&pem_private_key[512]);
    Crypto* get_crypto() { return m_crypto; }
    Encryptor* get_encryptor() { return m_encryptor; }
    //Attestation* get_attestation() { return m_attestation; }
  private:
    bool initialize(const char* name);
};
