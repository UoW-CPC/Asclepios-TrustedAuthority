// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <common/dispatcher.h>
#include <common/remoteattestation_t.h>
#include <enclave_b_pubkey.h>
#include <openenclave/enclave.h>
#include <string.h>
#include <stdio.h>
// For this purpose of this example: demonstrating how to do remote attestation
// g_enclave_secret_data is hardcoded as part of the enclave. In this sample,
// the secret data is hard coded as part of the enclave binary. In a real world
// enclave implementation, secrets are never hard coded in the enclave binary
// since the enclave binary itself is not encrypted. Instead, secrets are
// acquired via provisioning from a service (such as a cloud server) after
// successful attestation.
// The g_enclave_secret_data holds the secret data specific to the holding
// enclave, it's only visible inside this secured enclave. Arbitrary enclave
// specific secret data exchanged by the enclaves. In this sample, the first
// enclave sends its g_enclave_secret_data (encrypted) to the second enclave.
// The second enclave decrypts the received data and adds it to its own
// g_enclave_secret_data, and sends it back to the other enclave.
uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

enclave_config_data_t config_data = {g_enclave_secret_data,
                                     OTHER_ENCLAVE_PUBLIC_KEY,
                                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY)};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables

static ecall_dispatcher dispatcher("Enclave1", &config_data);

extern "C" ecall_dispatcher* get_dispatcher() { return &dispatcher;  }

const char* enclave_name = "Enclave1";
/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    TRACE_ENCLAVE("enter get_remote_report_with_pubkey");
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

// Attest and store the public key of another enclave.
int verify_report_and_set_pubkey(
    uint8_t* pem_key,
    size_t key_size,
    uint8_t* remote_report,
    size_t remote_report_size)
{
    return dispatcher.verify_report_and_set_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

/*
//AES-CBC
void initialize_encryptor(bool encrypt,unsigned char*key,size_t size)//,unsigned char** output_buf)
{
    TRACE_ENCLAVE("Initialize encryptor");
    //unsigned char* output_data = (unsigned char*)oe_host_malloc(size);
    //memcpy(output_data,key,size);
    // *output_buf = output_data;
    dispatcher.get_encryptor()->initialize(encrypt,key);
}

void initialize_encryptor_sealkey(bool encrypt,unsigned char*sealed_key,size_t size)//unsigned char** output_buf)
{
    TRACE_ENCLAVE("Initialize encryptor with sealed key");
    //unseal key
    unsigned char* output_data = (unsigned char*)oe_host_malloc(size);
    //memset(output_data,0,size);
    size_t out_data_len;
    unseal_bytes((uint8_t*)sealed_key,size,(uint8_t**)&output_data,&out_data_len);
    // *output_buf = output_data;
    dispatcher.get_encryptor()->initialize(encrypt,output_data);
    oe_host_free((void*)output_data);
}

void encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char** output_buf,
    size_t size,
    size_t*out_data_len)
{
    TRACE_ENCLAVE("Encrypt block");
    dispatcher.get_encryptor()->encrypt_block(encrypt, input_buf, output_buf, size,out_data_len);
}

void close_encryptor()
{
    dispatcher.get_encryptor()->close();
}
*/

// AES-CCM
void initialize_encryptor(unsigned char*key,size_t size)//,unsigned char** output_buf)
{
    TRACE_ENCLAVE("Initialize encryptor");
    //unsigned char* output_data = (unsigned char*)oe_host_malloc(size);
    //memcpy(output_data,key,size);
    // *output_buf = output_data;
    dispatcher.get_encryptor()->initialize(key);
}

void initialize_encryptor_sealkey(unsigned char*sealed_key,size_t size)//,unsigned char** output_buf)
{
    TRACE_ENCLAVE("Initialize encryptor with sealed key");
    //unseal key
    unsigned char* output_data = (unsigned char*)oe_host_malloc(size);
    //memset(output_data,0,size);
    size_t out_data_len;
    unseal_bytes((uint8_t*)sealed_key,size,(uint8_t**)&output_data,&out_data_len);

    //convert output_data to unsigned char*
    //*output_buf = output_data;
    
    // convert hex string (like "d8ccaa753e2983f03657ab3c8a68a85a") into array like  output_data1[] = {0xd8,0xcc,0xaa,0x75,0x3e,0x29,0x83,0xf0,0x36,0x57,0xab,0x3c,0x8a,0x68,0xa8,0x5a}
    unsigned char output_data1[size];

    for (int i = 0; i < size; i++) {
        sscanf((const char*)output_data + 2*i, "%02x", (unsigned int *)&output_data1[i]);
    }

    dispatcher.get_encryptor()->initialize((unsigned char*)output_data1); // AES-CCM
    oe_host_free((void*)output_data);
}

void encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char** output_buf,
    size_t size,
    size_t*out_data_len)
{
    TRACE_ENCLAVE("Encrypt block");
    dispatcher.get_encryptor()->encrypt_block(encrypt, input_buf, output_buf, size,out_data_len);
}

void close_encryptor()
{
    dispatcher.get_encryptor()->close();
}
