#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    std::cout << "Packet captured! Length: " << header->len << " bytes" << std::endl;

    const struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::cout << "Source IP: " << src_ip << std::endl;
        std::cout << "Destination IP: " << dst_ip << std::endl;
    } else {
        std::cout << "Non-IP packet captured." << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devices, *device;
    pcap_t *handle;

    if (pcap_findalldevs(&all_devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    device = all_devices;
    if (!device) {
        std::cerr << "No devices found!" << std::endl;
        return 1;
    }
    std::cout << "Using device: " << device->name << std::endl;

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Capturing packets..." << std::endl;
    pcap_loop(handle, 10, packet_handler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(all_devices);

    return 0;
}
