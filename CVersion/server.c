#include <msquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared.h"
#include "tun.h"
#include <pthread.h>

HQUIC RegistrationServer;
HQUIC ConfigurationServer;
HQUIC Listener;

QUIC_CREDENTIAL_CONFIG_HELPER ServerConfig = { 0 };



typedef struct {
    HQUIC Stream;
    pthread_t thread;
    int is_running;
} StreamThread;

#define MAX_STREAMS 10
StreamThread stream_threads[MAX_STREAMS] = { 0 };

void ServerSend(HQUIC Stream) {
    if (!Stream) {
        fprintf(stderr, "Error: Stream is NULL. Cannot send data.\n");
        return;
    }
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

    //unsigned char buffer[MAX_PACKET_SIZE];

    //// Allocate QUIC buffer
    //QUIC_BUFFER* quicBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER));
    //if (!quicBuffer) {
    //    fprintf(stderr, "Memory allocation failed for QUIC buffer.\n");
    //    return;
    //}

    //ssize_t bytesRead = tun_read(buffer, sizeof(buffer));

    //printf("[tun] Read %zd bytes from Tun0\n", bytesRead);

    //// Allocate buffer for QUIC transmission
    //quicBuffer->Buffer = (uint8_t*)malloc(bytesRead);
    //if (!quicBuffer->Buffer) {
    //    fprintf(stderr, "Memory allocation failed for buffer content.\n");
    //    free(quicBuffer);
    //    return;
    //}

    //// Copy actual received bytes into QUIC buffer
    //memcpy(quicBuffer->Buffer, buffer, bytesRead);
    //quicBuffer->Length = bytesRead;

    //// Send data over QUIC stream
    //QUIC_STATUS status = MsQuic->StreamSend(Stream, quicBuffer, 1, QUIC_SEND_FLAG_NONE, quicBuffer);
    //if (QUIC_FAILED(status)) {
    //    fprintf(stderr, "Failed to send packet to QUIC stream. Status: %d\n", status);
    //    free(quicBuffer->Buffer);
    //    free(quicBuffer);
    //    return;
    //}
    return QUIC_STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
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
        
        unsigned char buffer[1500] = { 0 };

        for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
            printf("[strm][%p] Data received bytes: %u\n", Stream, Event->RECEIVE.Buffers[i].Length);
            // Start writer thread if not running
            start_packet_writer();
            // Send data to the background buffer instead of writing immediately
            enqueue_packet_writer(Event->RECEIVE.Buffers[i].Buffer, Event->RECEIVE.Buffers[i].Length);
        }

        ServerSend(Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
)
{
    //UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        //MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
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
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
)
{
    //UNREFERENCED_PARAMETER(Listener);
    //UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, ConfigurationServer);
        break;
    default:
        break;
    }
    return Status;
}

BOOLEAN
ServerLoadConfiguration(
    //_In_ int argc, eventually pass certs in
    //_In_reads_(argc) _Null_terminated_ char* argv[]
    _In_ const char* server_ip,
    _In_ int port
)
{

    /*QUIC_STATUS Status;*/
    QUIC_SETTINGS Settings = { 0 };
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = FALSE;
    Settings.KeepAliveIntervalMs = 5000;

    Settings.InitialRttMs = 20;
    Settings.MaxAckDelayMs = 5;
    Settings.SendBufferingEnabled = FALSE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;

    QUIC_CREDENTIAL_CONFIG_HELPER ServerConfig = { 0 };

    const char* certFilePath = "/home/vagrant/server.cert";
    const char* keyFilePath = "/home/vagrant/server.key";

    /* Load TLS certificates */
    ServerConfig.CertFile.CertificateFile = (char*)certFilePath;
    ServerConfig.CertFile.PrivateKeyFile = (char*)keyFilePath;
    ServerConfig.CredConfig.Type = QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    ServerConfig.CredConfig.CertificateFile = &ServerConfig.CertFile;

    // For now don't implement until networking is working correctly.
    // Enable client authentication (mTLS)
    //Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;

    /* Create QUIC configuration */
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &RegistrationServer))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(RegistrationServer, &Alpn, 1, &Settings, sizeof(Settings), NULL, &ConfigurationServer))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    Status = MsQuic->ConfigurationLoadCredential(ConfigurationServer, &ServerConfig.CredConfig);
    if (QUIC_FAILED(Status)) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

int start_server(const char* server_ip, int port) {

    QUIC_STATUS Status;

    if (!ServerLoadConfiguration(server_ip, port)) {
        return 1;
    }

    /* Create QUIC listener */
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(RegistrationServer, ServerListenerCallback, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    inet_pton(AF_INET, server_ip, &Address.Ipv4.sin_addr);
    Address.Ipv4.sin_port = htons(port);

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("Server is running. Press Enter to exit...\n");
    getchar();

Error:

    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
        MsQuicClose(MsQuic);
        return 1;
    }
   
    return 0;
}