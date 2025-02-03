#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared.h"
#include "tun.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

HQUIC RegistrationClient;
HQUIC ConfigurationClient;

#define PING_INTERVAL 5  // Send ping every 5 seconds
#define TUN_DEVICE "tun0client" // Change if using a different TUN device
#define DEST_IP "10.20.0.10" // Destination to ping

// ICMP header structure
struct icmp_packet {
    struct icmphdr hdr;
    char data[56]; // Payload data
};


void ClientSend(_In_ HQUIC Connection, _In_ HQUIC Stream);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
)
{
    //UNREFERENCED_PARAMETER(Context);
    

    switch (Event->Type) {

    //case QUIC_STREAM_EVENT_SEND_COMPLETE:
    //    //
    //    // A previous StreamSend call has completed, and the context is being
    //    // returned back to the app.
    //    //
    //    free(Event->SEND_COMPLETE.ClientContext);
    //    printf("[strm][%p] Data sent\n", Stream);
    //    break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", Stream);
        unsigned char buffer[1500] = {0};

        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            printf("[strm][%p] Data received bytes: %u\n", Stream, Event->RECEIVE.Buffers[i].Length);
            // Start writer thread if not running
            start_packet_writer();
            // Send data to the background buffer instead of writing immediately
            enqueue_packet_writer(Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
        }
            
        ClientSend(NULL, Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void
ClientSend(
    _In_ HQUIC Connection,
    _In_ HQUIC Stream
)
{
    QUIC_STATUS Status;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (Stream == NULL) {

        if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &Stream))) {
            printf("StreamOpen failed, 0x%x!\n", Status);
        }
        printf("[strm][%p] Starting...\n", Stream);

        if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
            printf("StreamStart failed, 0x%x!\n", Status);
            MsQuic->StreamClose(Stream);
        }
    }

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    
    printf("[strm][%p] Sending Packet data...\n", Stream);

    start_tun_reader();

    PacketNode* packet = dequeue_packet();
    if (packet) {
        // Process packet data
        printf("[deque pkt] Processing packet of size: %zu bytes\n", packet->length);

        // Allocate QUIC buffer
        QUIC_BUFFER* quicBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
        if (!quicBuffer) {
            fprintf(stderr, "Memory allocation failed for QUIC buffer.\n");
            free(packet->data);
            free(packet);
            return;
        }
        quicBuffer->Buffer = (uint8_t*)malloc(packet->length);
        if (!quicBuffer->Buffer) {
            fprintf(stderr, "Memory allocation failed for buffer content.\n");
            free(quicBuffer);
            free(packet->data);
            free(packet);
            return;
        }
        memcpy(quicBuffer->Buffer, packet->data, packet->length);
        quicBuffer->Length = packet->length;

        // Send data over QUIC stream
        QUIC_STATUS status = MsQuic->StreamSend(Stream, quicBuffer, 1, QUIC_SEND_FLAG_NONE, quicBuffer);
        if (QUIC_FAILED(status)) {
            fprintf(stderr, "Failed to send packet to QUIC stream. Status: %d\n", status);
            free(quicBuffer->Buffer);
            free(quicBuffer);
            free(packet->data);
            free(packet);
            return;
        }
        printf("[strm][%p] Sent %zd bytes to QUIC stream.\n", Stream, packet->length);
        // Free packet memory
        free(packet->data);
        free(packet);
    }

    /*unsigned char buffer[1500] = {0};
    QUIC_BUFFER* quicBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
    if (!quicBuffer) {
        printf("Memory allocation failed for QUIC buffer.\n");
    }

    size_t bytesRead = tun_read(buffer, sizeof(buffer));
    if (bytesRead <= 0) {
        printf("No data read from tun device.\n");
        free(quicBuffer);
        return;
    }

    quicBuffer->Buffer = (uint8_t*)malloc(bytesRead);
    memcpy(quicBuffer->Buffer, buffer, bytesRead);
    quicBuffer->Length = bytesRead;
    
    printf("[strm][%p] Sending %d bytes to stream\n", Stream, quicBuffer->Length);
    QUIC_STATUS status = MsQuic->StreamSend(Stream, quicBuffer, 1, QUIC_SEND_FLAG_NONE, quicBuffer);
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "Failed to send packet to QUIC stream. Status: %d\n", status);
        return;
    }*/

    /*unsigned char buffer[5];
    strncpy((char*)buffer, "PING", 4);

    QUIC_BUFFER* quicBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
    if (!quicBuffer) {
        printf("Memory allocation failed for QUIC buffer.\n");
    }

    quicBuffer->Buffer = (uint8_t*)malloc(5);
    if (!quicBuffer->Buffer) {
        printf("Memory allocation failed for buffer content.\n");
        free(quicBuffer);
    }

    memcpy(quicBuffer->Buffer, buffer, sizeof(QUIC_BUFFER));
    quicBuffer->Length = sizeof(QUIC_BUFFER);*/

    /*start_tun_polling(Stream);*/
    return;
}

//Error:
//
//    if (QUIC_FAILED(Status)) {
//        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
//    }

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
)
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        ClientSend(Connection, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        }
        else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

BOOLEAN
ClientLoadConfiguration(
    BOOLEAN Unsecure
)
{

    QUIC_SETTINGS Settings = { 0 };
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = FALSE;
    Settings.KeepAliveIntervalMs = 5000;
    Settings.InitialRttMs = 20;
    Settings.MaxAckDelayMs = 5;
    Settings.SendBufferingEnabled = FALSE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &RegistrationClient))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(RegistrationClient, &Alpn, 1, &Settings, sizeof(Settings), NULL, &ConfigurationClient))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(ConfigurationClient, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

// Calculate ICMP checksum
unsigned short checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// Send ICMP Echo Request from the TUN interface
void send_icmp_ping(int sockfd, struct sockaddr_in* dest_addr) {
    struct icmp_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.hdr.type = ICMP_ECHO;
    packet.hdr.code = 0;
    packet.hdr.un.echo.id = htons(getpid() & 0xFFFF);
    packet.hdr.un.echo.sequence = htons(1);
    strcpy(packet.data, "Ping from TUN");

    // Compute ICMP checksum
    packet.hdr.checksum = checksum(&packet, sizeof(packet));

    if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)dest_addr, sizeof(*dest_addr)) < 0) {
        perror("Failed to send ICMP ping");
    }
    else {
        printf("[PING] Sent ICMP echo request to %s\n", inet_ntoa(dest_addr->sin_addr));
    }
}

int icmp() {

    int sockfd;
    struct sockaddr_in dest_addr;

    // Create raw socket to send ICMP packets
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Bind the socket to the TUN interface
    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, TUN_DEVICE, strlen(TUN_DEVICE));

    // Set up destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr);

    printf("[PING] Sending ICMP Echo Requests every %d seconds to %s via %s\n", PING_INTERVAL, DEST_IP, TUN_DEVICE);

    while (1) {
        send_icmp_ping(sockfd, &dest_addr);
        sleep(PING_INTERVAL);
    }

    close(sockfd);
    return 0;
}


void
start_client(
    const char* server_ip, 
    int port
) 
{
    HQUIC Connection = NULL;
    // Set insecure param to true for now.
    if (!ClientLoadConfiguration(TRUE)) {
        return;
    }

    //
    // Allocate a new connection object.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(RegistrationClient, ClientConnectionCallback, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[conn][%p] Connecting...\n", Connection);
    //
    // Start the connection to the server.
    //
    
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, ConfigurationClient, QUIC_ADDRESS_FAMILY_UNSPEC, server_ip, (uint16_t)port))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

    // hold connection open.
    getchar();
    //icmp();

Error:

    if (QUIC_FAILED(Status) && Connection != NULL) {
        MsQuic->ConnectionClose(Connection);
        printf("Failed to connect to server...");
    }

    return;
}



