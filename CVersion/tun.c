#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "msquic.h"
#include "shared.h"
#include "tun.h"

#define POLL_INTERVAL_US 10000
#define QUEUE_SIZE 1024
#define BUFFER_SIZE 4096

const char* TUN_DEVICE = "/dev/net/tun";
const int MAX_PACKET_SIZE = 1500;

typedef struct {
    unsigned char data[BUFFER_SIZE];
    size_t length;
} Packet;

Packet queue_w[QUEUE_SIZE];

volatile int headw = 0;
volatile int tailw = 0;
volatile int headr = 0;
volatile int tailr = 0;

pthread_mutex_t queue_lock_w = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond_w = PTHREAD_COND_INITIALIZER;

volatile int is_writer_running = 0;

pthread_t writer_thread_w;

typedef struct {
    int tun_fd;
} TUNHandle;

TUNHandle* TunHandl = NULL;

pthread_t tun_thread;        // Background thread
int thread_running = 0;      // Flag to prevent multiple threads

// Packet queue
PacketNode* queue_head = NULL;
PacketNode* queue_tail = NULL;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Function to create a TUN interface

void*
create_tun_interface(
    _In_ const char* IFACE_NAME
) 
{
    struct ifreq ifr;
    int tun_fd = open(TUN_DEVICE, O_RDWR);
    if (tun_fd < 0) {
        perror("Opening /dev/net/tun failed");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, IFACE_NAME, IFNAMSIZ);

    if (ioctl(tun_fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        close(tun_fd);
        return NULL;
    }

    printf("TUN interface %s created successfully!\n", ifr.ifr_name);

    TunHandl = (TUNHandle*)malloc(sizeof(TUNHandle));
    if (!TunHandl) {
        printf("Memory allocation failed for TUN handle.\n");
        close(tun_fd);
        return NULL;
    }

    TunHandl->tun_fd = tun_fd;
    return 0;
}

// Function to configure the TUN interface on the server
int 
configure_tun_interface_server(
    _In_ const char* IFACE_NAME
) 
{
    create_tun_interface(IFACE_NAME);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip addr add 10.20.0.10/30 peer 10.20.0.9 dev %s", IFACE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", IFACE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward");
    system(cmd);
    /*snprintf(cmd, sizeof(cmd), "ip route add default via 10.20.0.9 dev %s", IFACE_NAME);
    system(cmd);*/
    printf("Configured and brought up %s\n", IFACE_NAME);
    printf("=================================\n");
    return 0;
}

// Function to configure the TUN interface on the client
int
configure_tun_interface_client(
    _In_ const char* IFACE_NAME
) 
{
    create_tun_interface(IFACE_NAME);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip addr add 10.20.0.9/30 peer 10.20.0.10 dev %s", IFACE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up", IFACE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward");
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip route add default via 10.20.0.10 dev %s", IFACE_NAME);
    system(cmd);
    printf("Configured and brought up %s\n", IFACE_NAME);
    printf("=================================\n");
    return 0;
}

// Function to parse IPv4 packets
void 
process_packet(
    _In_ const unsigned char* data, 
    _In_ int length
) 
{
    if (length < sizeof(struct iphdr)) return;

    struct iphdr* ip_header = (struct iphdr*)data;
    int ip_header_length = ip_header->ihl * 4;
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;

    printf("\n========== IPv4 Packet ==========\n");
    printf("Src: %s -> Dst: %s\n", inet_ntoa(src_addr), inet_ntoa(dst_addr));

    if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr* icmp_header = (struct icmphdr*)(data + ip_header_length);
        printf("(ICMP) Type: %d, Code: %d\n", icmp_header->type, icmp_header->code);
    }
    else if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_length);
        printf("(TCP) Src Port: %d -> Dst Port: %d\n",
            ntohs(tcp_header->source), ntohs(tcp_header->dest));
    }
    printf("=================================\n");
}

// Function to enqueue a packet
void enqueue_packet(uint8_t* data, size_t length) {
    PacketNode* new_packet = (PacketNode*)malloc(sizeof(PacketNode));
    if (!new_packet) {
        perror("Failed to allocate packet node");
        return;
    }

    new_packet->data = (uint8_t*)malloc(length);
    if (!new_packet->data) {
        free(new_packet);
        perror("Failed to allocate packet data");
        return;
    }

    memcpy(new_packet->data, data, length);
    new_packet->length = length;
    new_packet->next = NULL;

    pthread_mutex_lock(&queue_mutex);

    if (queue_tail) {
        queue_tail->next = new_packet;
        queue_tail = new_packet;
    }
    else {
        queue_head = queue_tail = new_packet;
    }

    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

// Background thread function to read from TUN and enqueue data
void* tun_read_thread(void* arg) {
    uint8_t buffer[2048];

    while (thread_running) {
        if (!TunHandl) continue;

        ssize_t bytesRead = tun_read(buffer, sizeof(buffer));
        if (bytesRead > 0) {
            enqueue_packet(buffer, bytesRead);
        }
        else if (bytesRead < 0) {
            perror("Error reading from TUN device");
        }

        usleep(1000); // Small delay to prevent high CPU usage
    }

    return NULL;
}

// Function to start the background thread (ensuring only one instance)
void start_tun_reader() {
    if (!thread_running) {
        thread_running = 1;
        if (pthread_create(&tun_thread, NULL, tun_read_thread, NULL) != 0) {
            perror("Failed to create TUN reader thread");
            thread_running = 0;
        }
    }
}

// Function to dequeue and return a packet (caller must free it)
PacketNode* dequeue_packet() {
    pthread_mutex_lock(&queue_mutex);

    // Wait until a packet is available
    while (!queue_head) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }

    // Get the first packet from the queue
    PacketNode* packet = queue_head;
    queue_head = queue_head->next;

    // If the queue is now empty, reset the tail pointer
    if (!queue_head) {
        queue_tail = NULL;
    }

    pthread_mutex_unlock(&queue_mutex);
    return packet;  // Caller must free packet->data and packet
}

// Adds a packet to the queue (MsQuic Receive Thread)
void enqueue_packet_writer(const unsigned char* data, size_t length) {
    pthread_mutex_lock(&queue_lock_w);

    if ((tailw + 1) % QUEUE_SIZE == headw) {
        fprintf(stderr, "Queue full, dropping packet\n");
    }
    else {
        memcpy(queue_w[tailw].data, data, length);
        queue_w[tailw].length = length;
        tailw = (tailw + 1) % QUEUE_SIZE;
        pthread_cond_signal(&queue_cond_w);
    }

    pthread_mutex_unlock(&queue_lock_w);
}

// Removes and processes packets (Background Worker Thread)
void* packet_writer(void* arg) {
    while (1) {
        pthread_mutex_lock(&queue_lock_w);

        while (headw == tailw) {
            pthread_cond_wait(&queue_cond_w, &queue_lock_w);
        }
        while (headw != tailw) {
            Packet pkt = queue_w[headw];
            headw = (headw + 1) % QUEUE_SIZE;

            pthread_mutex_unlock(&queue_lock_w);  // Unlock while processing

            // Write to TUN
            ssize_t writtenBytes = tun_write(pkt.data, pkt.length);
            if (writtenBytes < 0) {
                perror("Error writing to TUN");
            }
            printf("[que] Wrote %zu bytes to packet IN que.\n", pkt.length);

            pthread_mutex_lock(&queue_lock_w);  // Re-lock for next packet
        }
        pthread_mutex_unlock(&queue_lock_w);
    }

    //    Packet pkt = queue_w[headw];
    //    headw = (headw + 1) % QUEUE_SIZE;

    //    pthread_mutex_unlock(&queue_lock_w);

    //    // Write to TUN
    //    ssize_t writtenBytes = tun_write(pkt.data, pkt.length);
    //    if (writtenBytes < 0) {
    //        perror("Error writing to TUN");
    //    }
    //    printf("[que] Wrote %zu bytes to packet IN que.\n", pkt.length);
    //}
    return NULL;
}

void start_packet_writer() {
    pthread_mutex_lock(&queue_lock_w);

    if (!is_writer_running) {
        if (pthread_create(&writer_thread_w, NULL, packet_writer, NULL) == 0) {
            is_writer_running = 1;
            pthread_detach(writer_thread_w);
        }
        else {
            perror("Failed to create TUN writer thread");
        }
    }

    pthread_mutex_unlock(&queue_lock_w);
}


// Function to read data from TUN interface
ssize_t tun_read(uint8_t* buffer, size_t size) {
    if (!TunHandl) return -1;

    size_t bytesRead = read(TunHandl->tun_fd, buffer, size);

    if (bytesRead < 0) {
        perror("Error reading from TUN device.");
    }
    else if (bytesRead == 0) {
        printf("No data available from TUN interface.\n");
    }
    else {
        printf("[tun] Successfully read %zd bytes from TUN interface.\n", bytesRead);
    }

    return bytesRead;
}

// Function to write data to TUN interface
ssize_t tun_write(uint8_t* buffer, size_t size) {
    if (!TunHandl) {
        fprintf(stderr, "Error: TUN handle is NULL.\n");
        return -1;
    }

    if (!buffer || size == 0) {
        fprintf(stderr, "Error: Invalid buffer or size (size=%zu).\n", size);
        return -1;
    }

    ssize_t bytesWritten = write(TunHandl->tun_fd, buffer, size);
    if (bytesWritten < 0) {
        perror("Error writing to TUN device");
    }
    else if ((size_t)bytesWritten != size) {
        fprintf(stderr, "Warning: Partial write to TUN (%zd/%zu bytes).\n", bytesWritten, size);
    }
    else {
        printf("[tun] Successfully wrote %zd bytes to TUN device.\n", bytesWritten);
    }

    return bytesWritten;
}


// Function to close the TUN handle
void tun_close() {
    if (TunHandl) {
        close(TunHandl->tun_fd);
        free(TunHandl);
    }
}

/**
 * Checks if the provided buffer contains a valid IPv4 packet.
 * Returns true if valid, false otherwise.
 */
BOOLEAN
is_valid_ip_packet(
    const unsigned char* buffer, 
    int length
) 
{
    if (!buffer) {
        fprintf(stderr, "Error: NULL packet buffer\n");
        return FALSE;
    }

    if (length < 20 || length > 1500) {
        fprintf(stderr, "Error: Packet size out of range (%d bytes)\n", length);
        return FALSE;
    }

    struct ip* ip_header = (struct ip*)buffer;

    // Check if it's IPv4 (version 4)
    if (ip_header->ip_v != 4) {
        fprintf(stderr, "Error: Not an IPv4 packet (version: %d)\n", ip_header->ip_v);
        return FALSE;
    }

    // Validate header length
    int ip_header_length = ip_header->ip_hl * 4;
    if (ip_header_length < 20 || ip_header_length > length) {
        fprintf(stderr, "Error: Invalid IP header length (%d bytes)\n", ip_header_length);
        return FALSE;
    }

    // Validate total length field
    int total_length = ntohs(ip_header->ip_len);
    if (total_length > length) {
        fprintf(stderr, "Error: IP packet length mismatch (Header: %d, Actual: %d)\n", total_length, length);
        return FALSE;
    }

    // Ensure the source and destination addresses are valid
    if (ip_header->ip_src.s_addr == 0 || ip_header->ip_dst.s_addr == 0) {
        fprintf(stderr, "Error: Invalid source/destination IP (Src: %s, Dst: %s)\n",
            inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        return FALSE;
    }

    process_packet(buffer, length);  // Display packet info
    // If all checks pass, the packet is valid
    return TRUE;
}

//void* tun_polling_routine(void* arg) {
//    HQUIC Stream = (HQUIC)arg;  // Correct pointer casting
//    if (!Stream) {
//        fprintf(stderr, "Error: Stream is NULL!\n");
//        return NULL;
//    }
//
//    printf("[strm][%p] Started polling loop.\n", Stream);
//
//    while (1) {
//        // Allocate buffer for the packet
//        QUIC_BUFFER* quicBuffer = read_tun();
//        if (!quicBuffer) {
//            usleep(POLL_INTERVAL_US);
//            continue;
//        }
//
//        if (!quicBuffer->Buffer || quicBuffer->Length <= 0) {
//            fprintf(stderr, "Error: Invalid TUN packet (Buffer=%p, Length=%d)\n",
//                quicBuffer->Buffer, quicBuffer->Length);
//            free(quicBuffer);
//            usleep(POLL_INTERVAL_US);
//            continue;
//        }
//        else {
//            QUIC_STATUS status = MsQuic->StreamSend(Stream, quicBuffer, 1, QUIC_SEND_FLAG_NONE, quicBuffer);
//            if (QUIC_FAILED(status)) {
//                fprintf(stderr, "Failed to send packet to QUIC stream. Status: %d\n", status);
//            }
//        }
//
//        // Free allocated resources
//        free(quicBuffer->Buffer);
//        free(quicBuffer);
//
//        // Short delay to prevent CPU overuse
//        usleep(POLL_INTERVAL_US);
//    }
//    printf("returning");
//    return NULL;
//}

/**
 * Starts the TUN polling function in a separate thread (Go-routine equivalent).
 */
//void start_tun_polling(HQUIC* Stream) {
//    pthread_t tun_thread;
//    if (pthread_create(&tun_thread, NULL, tun_polling_routine, (void*)Stream) != 0) {
//        perror("Error creating TUN polling thread");
//        exit(EXIT_FAILURE);
//    }
//
//    // Detach thread to run independently like a Go routine
//    pthread_detach(tun_thread);
//}
