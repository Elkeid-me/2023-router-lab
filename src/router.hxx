#include "router_prototype.hxx"
#include <cstdint>
#include <queue>
#include <unordered_map>

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

class Router : public RouterBase
{
private:
    std::unordered_map<std::uint32_t, std::uint32_t> m_nat_map;
    std::unordered_map<std::uint32_t, std::uint32_t> m_dv_map;
    std::unordered_map<std::uint32_t, bool> m_block_map;
    std::queue<std::uint32_t> m_available_external_addrs;

    int m_external_port{0};
    int m_port_num{0};

    int process_data_packet(int, char *);
    int process_dv_packet(int, char *);
    int process_control_packet(int, char *);

public:
    void router_init(int, int, char *, char *);
    int router(int, char *);
};
