#ifndef TUN_H
#define TUN_H

extern const char* TUN_DEVICE;
extern const int MAX_PACKET_SIZE;

#define QUEUE_SIZE 1024
#define BUFFER_SIZE 4096

typedef struct PacketNode {
    uint8_t* data;
    size_t length;
    struct PacketNode* next;
} PacketNode;

extern void start_packet_writer();
extern void enqueue_packet_writer(const unsigned char* data, size_t length);
extern PacketNode* dequeue_packet();
extern void start_tun_reader();

extern ssize_t tun_read(uint8_t* buffer, size_t size);
extern ssize_t tun_write(uint8_t* buffer, size_t size);

extern BOOLEAN is_valid_ip_packet(const unsigned char* buffer, int length);
extern void process_packet(_In_ const unsigned char* data, _In_ int length);

extern int configure_tun_interface_server(_In_ const char* IFACE_NAME);
extern int configure_tun_interface_client(_In_ const char* IFACE_NAME);

extern int tun_fd;

#endif  // TUN_H


