#include <stdio.h>
#include <stdlib.h>
#include "msquic.h"

QUIC_API_TABLE* MsQuic;

const uint32_t SendBufferLength = 100;
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };
const QUIC_REGISTRATION_CONFIG RegConfig = { "quic-proxy", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const uint64_t IdleTimeoutMs = 60000;
QUIC_ADDR Address = { .Ip.sa_family = AF_INET };

QUIC_STATUS initialize_msquic() {
    return MsQuicOpen2(&MsQuic);
}
