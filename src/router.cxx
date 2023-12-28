#include "router.hxx"
#include <bit>
#include <cstdint>

template <typename T>
    requires(sizeof(T) == sizeof(std::uint32_t))
T byte_swap(T x)
{
    return __builtin_bswap32(static_cast<std::uint32_t>(x));
}

std::uint32_t header::get_src() const { return byte_swap(src); }
std::uint32_t header::get_dst() const { return byte_swap(dst); }
header_type header::get_type() const { return type; }
std::uint16_t header::get_length() const { return length; }
void header::make_header(std::uint32_t _src, std::uint32_t _dst, header_type _type,
                         std::uint16_t _length)
{
    src = byte_swap(_src);
    dst = byte_swap(_dst);
    type = _type;
    length = _length;
}

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(header) == 12);

RouterBase *create_router_object() { return new Router; }

void Router::router_init(int port_num, int external_port, char *external_addr,
                         char *available_addr)
{
    return;
}

int Router::router(int in_port, char *packet)
{
    const header *header_ptr{reinterpret_cast<header *>(packet)};
    return 0;
}
