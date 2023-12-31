#include "router.hxx"
#include <bit>
#include <cstdint>

template <typename T>
    requires(sizeof(T) == sizeof(std::uint32_t))
T byte_swap(T x)
{
    return __builtin_bswap32(static_cast<std::uint32_t>(x));
}

std::uint32_t header::get_src() const { return byte_swap(m_src); }
std::uint32_t header::get_dst() const { return byte_swap(m_dst); }
header_type header::get_type() const { return m_type; }
std::uint16_t header::get_length() const { return m_length; }

void header::set_src(std::uint32_t _src) { m_src = byte_swap(_src); }
void header::set_dst(std::uint32_t _dst) { m_dst = byte_swap(_dst); }
void header::set_type(header_type _type) { m_type = _type; }
void header::set_length(std::uint16_t _length) { m_length = _length; }

void header::make_header(std::uint32_t _src, std::uint32_t _dst, header_type _type,
                         std::uint16_t _length)
{
    m_src = byte_swap(_src);
    m_dst = byte_swap(_dst);
    m_type = _type;
    m_length = _length;
}

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(header) == 12);

static bool is_external_address(std::uint32_t ip) { return (ip >> 24) ^ 0x0A; }

RouterBase *create_router_object() { return new Router; }

int Router::process_data_packet(int in_port, char *packet)
{
    header *header_ptr{reinterpret_cast<header *>(packet)};
    std::uint32_t src{header_ptr->get_src()}, dst{header_ptr->get_dst()};
}

void Router::router_init(int port_num, int external_port, char *external_addr,
                         char *available_addr)
{
}

int Router::router(int in_port, char *packet)
{
    const header *header_ptr{reinterpret_cast<header *>(packet)};
    switch (header_ptr->get_type())
    {
    case header_type::data:
        return process_data_packet(in_port, packet);
    case header_type::dv:
        return process_dv_packet(in_port, packet);
    case header_type::control:
        return process_control_packet(in_port, packet);
    default:
        return -1;
    }
}
