
#include <pcap.h>
#include <iostream>
#include <map>
#include <vector>

struct PacketSize {
    int size;
    int count;
};

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        std::cerr << "pcap_open_live: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Capturing traffic..." << std::endl;

    int packet_count = 0;
    int byte_count = 0;
    int min_packet_size = INT_MAX;
    int max_packet_size = 0;
    std::map<std::pair<std::string, std::string>, int> src_dst_pairs;
    std::vector<PacketSize> packet_sizes;
    std::map<int, int> packet_size_distribution;

    pcap_loop(handle, 0, [](u_char* args, const pcap_pkthdr* header, const u_char* bytes) {
        packet_count++;
        byte_count += header->len;
        min_packet_size = std::min(min_packet_size, header->len);
        max_packet_size = std::max(max_packet_size, header->len);

        // Extract source and destination IP addresses and ports
        struct iphdr* iph = (struct iphdr*)(bytes + 14);
        struct tcphdr* tcph = (struct tcphdr*)((char*)iph + iph->ihl * 4);
        std::string src_ip(inet_ntoa(iph->saddr));
        std::string dst_ip(inet_ntoa(iph->daddr));
        int src_port = ntohs(tcph->source);
        int dst_port = ntohs(tcph->dest);

        // Update source-destination pairs
        std::pair<std::string, std::string> pair = std::make_pair(src_ip + ":" + std::to_string(src_port), dst_ip + ":" + std::to_string(dst_port));
        src_dst_pairs[pair]++;

        // Update packet sizes
        PacketSize ps;
        ps.size = header->len;
        ps.count = 1;
        packet_sizes.push_back(ps);

        // Update packet size distribution
        packet_size_distribution[header->len]++;

        return;
    }, NULL);

    std::cout << "Packet count: " << packet_count << std::endl;
    std::cout << "Byte count: " << byte_count << std::endl;
    std::cout << "Minimum packet size: " << min_packet_size << std::endl;
    std::cout << "Maximum packet size: " << max_packet_size << std::endl;
    std::cout << "Average packet size: " << (double)byte_count / packet_count << std::endl;

    // Print source-destination pairs
    std::cout << "Unique source-destination pairs:" << std::endl;
    for (const auto& pair : src_dst_pairs) {
        std::cout << pair.first.first << " -> " << pair.first.second << std::endl;
    }

    // Print packet size distribution
    std::cout << "Packet size distribution:" << std::endl;
    for (const auto& pair : packet_size_distribution) {
        std::cout << "Size: " << pair.first << ", Count: " << pair.second << std::endl;
    }

    // Plot histogram of packet sizes
    std::cout << "Plotting histogram of packet sizes..." << std::endl;
    // You can use a library like gnuplot or matplotlib to plot the histogram

    pcap_close(handle);
    return 0;
}
