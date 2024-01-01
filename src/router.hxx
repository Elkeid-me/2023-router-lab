#include "router_prototype.hxx"
#include <cstdint>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum class header_type : std::uint8_t
{
    dv = 0x00,
    data = 0x01,
    control = 0x02
};

enum class command_type
{
    trigger_dv_send = 0,
    release_nat_term = 1,
    port_value_change = 2,
    add_host = 3,
    block_addr = 5,
    unblock_addr = 6
};

class header
{
private:
    std::uint32_t m_src;
    std::uint32_t m_dst;
    header_type m_type;
    std::uint16_t m_length;

public:
    std::uint32_t get_src() const;
    std::uint32_t get_dst() const;
    header_type get_type() const;
    std::uint16_t get_length() const;

    void set_src(std::uint32_t);
    void set_dst(std::uint32_t);
    void set_type(header_type);
    void set_length(std::uint16_t);

    void make_header(std::uint32_t, std::uint32_t, header_type, std::uint16_t);
};

struct map_entry
{
    std::uint32_t distance;
    int port;
};

struct dv_table_entry
{
    std::uint32_t ip;
    std::uint32_t distance;
};

struct ex_map_key
{
    std::uint32_t start;
    std::uint32_t end;
};

struct ex_dv_table_entry
{
    ex_map_key ip_range;
    std::uint32_t distance;
};

class Router : public RouterBase
{
private:
    // nat 映射，从内网地址到外网地址; nat 逆映射，从外网地址到内网地址.
    std::unordered_map<std::uint32_t, std::uint32_t> m_nat_map, m_reverse_nat_map;
    // 内网距离向量表与路由表.
    std::unordered_map<std::uint32_t, map_entry> m_dv_map;
    // 外网距离向量表与路由表.
    std::map<ex_map_key, map_entry, std::less<>> m_ex_dv_map;
    // 被屏蔽的源地址.
    std::unordered_set<std::uint32_t> m_block;
    // 可用的外网地址集合.
    std::vector<std::uint32_t> m_available_addrs;
    // 各个端口的权重.
    std::vector<int> m_port_value;

    int m_ex_port{0};
    int m_port_num{0};

    int process_data_packet(int, char *);
    int process_dv_packet(int, char *);
    int process_control_packet(int, char *);

    void packet_dv(char *);

    void release_nat(char *);
    void port_value_change(char *);
    void add_host(char *);
    void block(char *);
    void unblock(char *);

public:
    void router_init(int, int, char *, char *);
    int router(int, char *);
};
