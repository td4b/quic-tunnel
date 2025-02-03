#ifndef SHARED_H
#define SHARED_H
#include "msquic.h"

extern const QUIC_API_TABLE* MsQuic;

extern QUIC_STATUS initialize_msquic();
extern uint32_t SendBufferLength;
extern const QUIC_BUFFER Alpn;
extern const QUIC_REGISTRATION_CONFIG RegConfig;
extern const uint64_t IdleTimeoutMs;
extern QUIC_ADDR Address;

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

#endif // SHARED_H