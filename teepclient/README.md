# Build

To build you must set the open enclave environment variables (I do it in .bashrc):

```
. /opt/openenclave/share/openenclave/openenclaverc
```

Then just do `make`

# Demo requirements

To install the required libraries, do
```
conda install pip ipython pycryptodome 
pip install cbor aiocoap
```

# TEEP sample

This directory contains code to launch secure enclaves via a coap server that listens to
TEEP-like messages
- query
- install
- delete
- info

The file `simple.py` shows how to start a coap server, and how to send it CBOR-encoded TEEP messages.

The coap-server is started with

    python -c 'import simple; simple.start_server()'
    
Two enclave binaries are provided.  They can remotely attest each other, showing that they talk
to legitimate secure instances.

To install the enclave_a on the server, and attest it, do

    python -c 'import simple; simple.sealingtest()'


In `simple.test()`, the binary for `enclave_a` is sent to the coap-server in a TEEP install message.
The server (TEEP Agent) uses `lib.py` to install and start the enclave.  The agent then asks the enclave for
a report, which is returned to us together with a freshly generated public RSA key.

Next, the we use remote attestation to verify that the report and key is indeed from a valid enclave running the
code in `enclave_a`.

We encrypt some private data with the provided key, and sends it back to the enclave.
(This is not working yet, as I haven't gotten the RSA_OEAP in python and mbedtls to talk nicely with
each other yet.)


The enclave does whatever processing is required.  It then returns data for us to hold on to.
This data is sealed, meaning only secure instances of `enclave_a` typke can unpack it and
continue processing.


(A compact example showing how to use `lib.py` to create and attest instances can be found in `example1.py`)


# How to use this

If you want to make an application that processes information in an enclave,
you need to modify the code in `enclave_a`, which is the C / C++ code that 
runs in the enclave.

To write programs that install and talk to the enclaves, use the python library
in `lib.py` which wraps the C function calls to the open enclave functions.


# OCSP validation using openssl

This shows how to validate certificates using openssl, but should be converted to
a proper programing language.  It uses the certificates in `attic/certs`.

```
cd attic
. ocsp_validation_with_openssl.sh
verify www.twitter.com:443
```

# ATTENTION:

This code is based on the example code in OpenEnclave and contains the application secrets in clear text,
and the private keys for signing the enclaves are also generated during the build process.  To be
used in a secure deployment, these secrets have to be handled in an organized and systematic manner.

