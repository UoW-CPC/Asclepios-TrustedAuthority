addrootof () (
    HOST=${1:-}
    # get the chain of certificates sent by the server
    true | openssl s_client -showcerts -connect $HOST > chain.pem
    ROOT_CERT_URL=$(openssl x509 -noout -in chain.pem  -ext authorityInfoAccess |
        awk '/CA Issuers - URI/' | cut -d: -f2-)
    curl --output certs/$HOST.crt $ROOT_CERT_URL
    openssl x509 -inform DER -in certs/$HOST.crt  -outform PEM -out certs/$HOST.pem &&
        rm certs/$HOST.crt
    openssl rehash certs

    rm chain.pem
)

verify() (
    HOST=${1:-}
    # get the host's certificate
    true | openssl s_client -connect $HOST > certificate.pem
    # get the chain of certificates sent by the server
    true | openssl s_client -showcerts -connect $HOST > chain.pem
    OCSPURL=$(openssl x509 -noout -ocsp_uri -in chain.pem)
    ISSUER_HASH=$(openssl x509 -noout -issuer_hash -in chain.pem)
    #  verify assuming we have the issuer_s certificate in the certs dir
    openssl ocsp -issuer certs/${ISSUER_HASH}.0 -no_nonce -cert certificate.pem -text -url $OCSPURL
)

example_verify() (
   mkdir certs
   verify www.ri.se:443
   addrootof www.ri.se:443
   verify www.ri.se:443
)

