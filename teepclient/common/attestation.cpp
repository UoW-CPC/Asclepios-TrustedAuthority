// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"

// for seal_bytes()
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>

void dump(const uint8_t *d, size_t n)
{
  for(int i = 0; i<n; i++)
    { printf("%02x%s", d[i],((i+1)%16==0)?"\n":""); }
  if(n%16!=0) printf("\n");
}


#define IV_SIZE 16
#define CIPHER_BLOCK_SIZE 16


int random_bytes(uint8_t* b, size_t size)
{
    // intitalize crypto 
    mbedtls_ctr_drbg_context m_ctr_drbg_contex;
    mbedtls_entropy_context m_entropy_context;
    const char pers[] = "random data string";  // needed by mbedtlis_ctr_dbrg_seed
    unsigned char bts[size];

    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
    
    mbedtls_ctr_drbg_seed(
      &m_ctr_drbg_contex,
     mbedtls_entropy_func,
     &m_entropy_context,
     (unsigned char*)pers,
     sizeof(pers));

    // draw random numbers
    int ret = mbedtls_ctr_drbg_random(&m_ctr_drbg_contex, bts, size);

    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);
    
    if (ret !=0) {
      TRACE_ENCLAVE("random_bytes failed! %d",ret);
      return ret;
    }

    memcpy(b, bts, size);
    return 0;
}

#include <common/dispatcher.h>
extern "C" ecall_dispatcher* get_dispatcher();

// seal_bytes is called from the outside with data that by
// this function gets encrypted with an aes key derived from the
// MRSIGNER register, i.e. the sealed data can only be decrypted by
// (depending on the seal policy) this exact program running in a
//  secure enclave, or by another program signed with the same
//  private key as this.


// In this example, the data should be pkcs1.5 encrypted with this enclaves public key.
// We decrypt the data, seal it with an AES seal key, and return it (for demonstation purposes)

extern"C" int seal_bytes(const uint8_t* data, size_t data_size, uint8_t** out_data, size_t* out_data_len)
{
  int ret;

  if (data_size % CIPHER_BLOCK_SIZE != 0)
    {  TRACE_ENCLAVE("Bad input: the data size must be a multiple of %d.", CIPHER_BLOCK_SIZE);
       return 1;
    }
  
  // get key
    int seal_policy = OE_SEAL_POLICY_PRODUCT; // or POLICY_UNIQUE;
    uint8_t* seal_key;    
    size_t seal_key_size; 
    uint8_t* key_info;    
    size_t key_info_size; 
    oe_result_t result;

    uint8_t decr[256];
    memset(decr, 0, data_size);
    size_t decr_len = sizeof(decr);

    Crypto* crypto = get_dispatcher()->get_crypto();
    ret = crypto->test_decrypt(data, data_size, decr, &decr_len);
    
    result = oe_get_seal_key_by_policy(
      (oe_seal_policy_t)seal_policy, &seal_key, &seal_key_size, &key_info, &key_info_size);
    if (result != OE_OK)
      {
        TRACE_ENCLAVE("got error from get_seal_key_by_policy: %s", (char*)oe_result_str(result));
        return ret;
      }

    uint8_t* output_data = (uint8_t*)oe_host_malloc(IV_SIZE+data_size);
    if(output_data == NULL)
      {
        TRACE_ENCLAVE("Error: malloc failed");
        return 1;
      }
    memset(output_data, 0, data_size);
    
    // create a random IV stored in the first bytes of the output data
    uint8_t* iv = output_data;
    ret = random_bytes(iv, IV_SIZE);
    if (ret != 0)  { return ret; }
    
    uint8_t local_iv[IV_SIZE];
    memcpy(local_iv, iv, IV_SIZE);

    // encrypt message ------------------------------

    mbedtls_aes_context aescontext;
    mbedtls_aes_init(&aescontext);
    mbedtls_aes_setkey_enc(&aescontext, seal_key, seal_key_size*8);

     // pad to multiple of 16 for AES
    decr_len += 1;  // add a byte (after the padding zeros) to hold the number of padbytes needed
    int pad = 16 - (decr_len % 16); pad = (pad==16)?0:pad;
    memset(&decr[decr_len],0,pad);
    decr[decr_len+pad-1] = pad+1;
    decr_len += pad;
    
    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        MBEDTLS_AES_ENCRYPT,
        decr_len,    // input data length in bytes
        local_iv,    // Initialization vector (updated after use)
        decr,
        output_data+IV_SIZE); // store encrypted data after the IV

    if(ret!=0) {
      TRACE_ENCLAVE("couldnt encrypt data (len=%ld oldlen=%ld): %d", decr_len, data_size, ret);
    }
    
    *out_data = output_data;
    *out_data_len = decr_len + IV_SIZE;
    
    mbedtls_aes_free(&aescontext);

    return 0;
}

//  This is used for testing that everything works.
//  One shouldnt really let all the clear text of the data
//  be exported out of the secure enclave.
extern"C" int unseal_bytes(const uint8_t* data, size_t data_size, uint8_t** out_data, size_t* out_data_len)
{
  int ret;
  
  if ((data_size-IV_SIZE) % CIPHER_BLOCK_SIZE != 0)
    {  TRACE_ENCLAVE("Bad input: the data size must be a multiple of %d.", CIPHER_BLOCK_SIZE);
       return 1;
    }
    
    const uint8_t* iv = data;
    data += IV_SIZE;
    data_size -= IV_SIZE;
  
  // get key
    int seal_policy = OE_SEAL_POLICY_PRODUCT; // or POLICY_UNIQUE;
    uint8_t* seal_key;    
    size_t seal_key_size; 
    uint8_t* key_info;    
    size_t key_info_size; 
    oe_result_t result;

    result = oe_get_seal_key_by_policy(
      (oe_seal_policy_t)seal_policy, &seal_key, &seal_key_size, &key_info, &key_info_size);
    if (result != OE_OK)
      {
        TRACE_ENCLAVE("got error from get_seal_key_by_policy: %s", (char*)oe_result_str(result));
        return ret;
      }


    uint8_t* output_data = (uint8_t*)oe_host_malloc(data_size);
    if(output_data == NULL)
      {
        TRACE_ENCLAVE("Error: malloc failed");
        return 1;
      }
    memset(output_data, 0, data_size);
    
    uint8_t local_iv[IV_SIZE];
    memcpy(local_iv, iv, IV_SIZE);

    // decrypt message ------------------------------

    mbedtls_aes_context aescontext;
    mbedtls_aes_init(&aescontext);
    mbedtls_aes_setkey_dec(&aescontext, seal_key, seal_key_size*8);

    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        MBEDTLS_AES_DECRYPT,
        data_size,        // input data length in bytes,
        local_iv,        // Initialization vector (updated after use)
        data,
        output_data); 

    if(ret!=0) {
      TRACE_ENCLAVE("couldnt decrypt data: %d", ret);
    }
    
    
    *out_data = output_data;
    *out_data_len = data_size;

    // remove padding added in seal_bytes
    if(data_size >= output_data[data_size-1])
        *out_data_len -= output_data[data_size-1];
    
    mbedtls_aes_free(&aescontext);

    return 0;
}


Attestation::Attestation(Crypto* crypto, uint8_t* enclave_mrsigner)
{
    m_crypto = crypto;
    m_enclave_mrsigner = enclave_mrsigner;
}

/**
 * Generate a remote report for the given data. The SHA256 digest of the data is
 * stored in the report_data field of the generated remote report.
 */
bool Attestation::generate_remote_report(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** remote_report_buf,
    size_t* remote_report_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    uint8_t* temp_buf = NULL;
    
    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    // To generate a remote report that can be attested remotely by an enclave
    // running  on a different platform, pass the
    // OE_REPORT_FLAGS_REMOTE_ATTESTATION option. This uses the trusted
    // quoting enclave to generate the report based on this enclave's local
    // report.
    // To generate a remote report that just needs to be attested by another
    // enclave running on the same platform, pass 0 instead. This uses the
    // EREPORT instruction to generate this enclave's local report.
    // Both kinds of reports can be verified using the oe_verify_report
    // function.
    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        sha256, // Store sha256 in report_data field
        sizeof(sha256),
        NULL, // opt_params must be null
        0,
        &temp_buf,
        remote_report_buf_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_report failed.");
        goto exit;
    }
    *remote_report_buf = temp_buf;
    ret = true;
    

exit:
    return ret;
}

/**
 * Attest the given remote report and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The remote report is first attested using the oe_verify_report API. This
 * ensures the authenticity of the enclave that generated the remote report.
 * 2) Next, to establish trust of the enclave that  generated the remote report,
 * the mrsigner, product_id, isvsvn values are checked to  see if they are
 * predefined trusted values.
 * 3) Once the enclave's trust has been established, the validity of
 * accompanying data is ensured by comparing its SHA256 digest against the
 * report_data field.
 */
bool Attestation::attest_remote_report(
    const uint8_t* remote_report,
    size_t remote_report_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_report_t parsed_report = {0};
    oe_result_t result = OE_OK;

    // While attesting, the remote report being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(remote_report, remote_report_size))
    {
        TRACE_ENCLAVE("Cannot attest remote report in host memory. Unsafe.");
        goto exit;
    }

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    result =
        oe_verify_report(remote_report, remote_report_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_report failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    // 2) validate the enclave identity's signed_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.
    if (memcmp(parsed_report.identity.signer_id, m_enclave_mrsigner, 32) != 0)
    {
        TRACE_ENCLAVE("identity.signer_id checking failed.");
        TRACE_ENCLAVE(
            "identity.signer_id %s", parsed_report.identity.signer_id);

        for (int i = 0; i < 32; i++)
        {
            TRACE_ENCLAVE(
                "m_enclave_mrsigner[%d]=0x%0x\n",
                i,
                (uint8_t)m_enclave_mrsigner[i]);
        }

        TRACE_ENCLAVE("\n\n\n");

        for (int i = 0; i < 32; i++)
        {
            TRACE_ENCLAVE(
                "parsedReport.identity.signer_id)[%d]=0x%0x\n",
                i,
                (uint8_t)parsed_report.identity.signer_id[i]);
        }
        TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
        goto exit;
    }

    // Check the enclave's product id and security version
    // See enc.conf for values specified when signing the enclave.
    if (parsed_report.identity.product_id[0] != 1)
    {
        TRACE_ENCLAVE("identity.product_id checking failed.");
        goto exit;
    }

    if (parsed_report.identity.security_version < 1)
    {
        TRACE_ENCLAVE("identity.security_version checking failed.");
        goto exit;
    }

    // 3) Validate the report data
    //    The report_data has the hash value of the report data
    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0)
    {
        TRACE_ENCLAVE("SHA256 mismatch.");
        goto exit;
    }
    ret = true;
    // TRACE_ENCLAVE("remote attestation succeeded.");
exit:
    return ret;
}
