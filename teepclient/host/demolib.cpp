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


