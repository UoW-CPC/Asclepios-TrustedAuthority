// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include "remoteattestation_u.h"


extern "C" oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_remoteattestation_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}


int file_to_bytes(const char *filename, char** bytes, size_t* bytes_len)
{
    FILE *fp = fopen(filename, "rb");
    if (fp==NULL) {
      printf("couldn't open %s\n", filename);
      return 1;
    }

    // get file length
    fpos_t p;
    if(fgetpos(fp, &p) == 0)
      {
        fseek(fp, 0L, SEEK_END);
        *bytes_len = (size_t)ftell(fp);
        fsetpos(fp, &p);
      }
    else
      {
        printf("couldnt fgetpos");
        return 1;
      }

    *bytes = (char*)mmap(NULL, *bytes_len, PROT_READ, MAP_PRIVATE, fileno(fp), 0);
    fclose(fp);
    if (bytes == MAP_FAILED)
      {
        printf("mmap failed.\n");
        return 1;
      }
    return 0;
}

extern "C" oe_enclave_t* create_enclave_bytes(const char* enclave_bytes, size_t len_bytes)
{
#define TEMPLATE "/tmp/myTmpFile-XXXXXX"
  char* filename;
  filename = (char *)malloc(strlen(TEMPLATE)+1);
  strcpy(filename, TEMPLATE);
  int f = mkstemp(filename);
  oe_enclave_t* enclave = NULL;
  if (f < 0)
    {
      printf("FAIL: Couldn't create file %s.\n", filename);
    }
  else
    {
      printf("Ok, Created file %s.\n", filename);
      if (write(f, enclave_bytes, len_bytes) != len_bytes)
        {
          printf("FAIL: couldn't write the bytes to the file\n");
        }
      else
        {
          enclave = create_enclave(filename);
        }
      close(f);
      unlink(filename);
    }
  return enclave;
}



extern "C" void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}



extern "C" int getpubkey(oe_enclave_t* enclave,
                         uint8_t** pem_key, size_t* pem_key_size,
                         uint8_t** remote_report, size_t* remote_report_size
                         )
{
  oe_result_t result = OE_OK;
  int ret = 1;

  result = get_remote_report_with_pubkey(
        enclave,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if (result == OE_OK && ret == 0)
      {
  
      }
    else
    {
        printf(
            "Host: get_remote_report_with_pubkey failed: %s",
            oe_result_str(result));
        ret = 1;
    }
    return ret;
    
}

extern "C" int verifyreport(oe_enclave_t* enclave,
                            uint8_t* pem_key, size_t pem_key_size,
                            uint8_t* remote_report, size_t remote_report_size)
{
  oe_result_t result = OE_OK;
  int ret = 1;

  result = verify_report_and_set_pubkey(
        enclave,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
  if (result == OE_OK && ret == 0)
    {
    }
  else
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s, ret=%d",
            oe_result_str(result), ret);
        ret = 1;
    }
    return ret;

}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;

    /* Check argument count */
    if (argc != 3)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("Host: Creating two enclaves\n");
    {
      char* bytes;
      size_t bytes_len;
      file_to_bytes(argv[1], &bytes, &bytes_len);
      enclave_a = create_enclave_bytes(bytes, bytes_len);
      munmap(bytes, bytes_len);
    }
    {
      char* bytes;
      size_t bytes_len;
      file_to_bytes(argv[2], &bytes, &bytes_len);
      enclave_b = create_enclave_bytes(bytes, bytes_len);
      munmap(bytes, bytes_len);
    }

    if (enclave_a == NULL || enclave_b == NULL)
    {
        goto exit;
    }
      
    printf("Host: requesting a remote report and the encryption key from 1st "
           "enclave\n");
    result = get_remote_report_with_pubkey(
        enclave_a,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: 1st enclave's public key: \n%s", pem_key);

    printf("Host: requesting 2nd enclave to attest 1st enclave's the remote "
           "report and the public key\n");
    result = verify_report_and_set_pubkey(
        enclave_b,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Requesting a remote report and the encryption key from "
           "2nd enclave=====\n");
    result = get_remote_report_with_pubkey(
        enclave_b,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: 2nd enclave's public key: \n%s", pem_key);

    printf("Host: Requesting first enclave to attest 2nd enclave's "
           "remote report and the public key=====\n");
    result = verify_report_and_set_pubkey(
        enclave_a,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Remote attestation Succeeded\n");

    // Free host memory allocated by the enclave.
    free(encrypted_msg);
    encrypted_msg = NULL;
    ret = 0;

exit:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
