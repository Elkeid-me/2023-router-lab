#include "router_prototype.hxx"
#include <cstdint>

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
    std::uint32_t src;
    std::uint32_t dst;
    header_type type;
    std::uint16_t length;

public:
    std::uint32_t get_src() const;
    std::uint32_t get_dst() const;
    header_type get_type() const;
    std::uint16_t get_length() const;

    void make_header(std::uint32_t, std::uint32_t, header_type, std::uint16_t);
};

class Router : public RouterBase
{
public:
    void router_init(int port_num, int external_port, char *external_addr,
                     char *available_addr);
    int router(int in_port, char *packet);
};
