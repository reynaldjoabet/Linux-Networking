#include <sys/socket.h>
#include <unistd.h>
#include <net/ethernet.h> // struct ether_header and ETHERTYPE_*
// #include <net/if_ether.h> // ARP and other Ethernet-level definitions
#include <net/if.h> // Interface structures

struct eth_hdr
{
    unsigned char dmac[6];
    unsigned char smac[6];
    uint16_t ethertype;
    unsigned char payload[];
} __attribute__((packed));

int main()
{
    int sockfds[2];
    // socketpair() creates two connected sockets; both ends can read/write.
    socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds); // Full-duplex pipe

    write(sockfds[0], "Hello", 5);
    char buf[10];
    read(sockfds[1], buf, 5);

    write(1, buf, 5); // Write to stdout (fd 1)
    return 0;
}
