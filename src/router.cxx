#include "router.hxx"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <ranges>
#include <span>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

template <typename T>
    requires(sizeof(T) == sizeof(std::uint32_t))
T byte_swap(T x)
{
    return __builtin_bswap32(static_cast<std::uint32_t>(x));
}

template <typename... V> void debug(V... args)
{
    ((std::cout << "\033[32;1m[DEBUG]\033[0m ") << ... << args) << '\n';
}

#define log_debug(...) ::debug(__VA_ARGS__)

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

static std::uint32_t parser_ip_str(const char *ip)
{
    in_addr ipv4_addr;
    inet_aton(ip, &ipv4_addr);
    return byte_swap(ipv4_addr.s_addr);
}

static std::pair<std::uint32_t, std::uint32_t> parser_ip_range(char *ip)
{
    constexpr static std::uint32_t mask_1[33]{
        0x00'00'00'00u, 0x80'00'00'00, 0xc0'00'00'00, 0xe0'00'00'00, 0xf0'00'00'00,
        0xf8'00'00'00,  0xfc'00'00'00, 0xfe'00'00'00, 0xff'00'00'00, 0xff'80'00'00,
        0xff'c0'00'00,  0xff'e0'00'00, 0xff'f0'00'00, 0xff'f8'00'00, 0xff'fc'00'00,
        0xff'fe'00'00,  0xff'ff'00'00, 0xff'ff'80'00, 0xff'ff'c0'00, 0xff'ff'e0'00,
        0xff'ff'f0'00,  0xff'ff'f8'00, 0xff'ff'fc'00, 0xff'ff'fe'00, 0xff'ff'ff'00,
        0xff'ff'ff'80,  0xff'ff'ff'c0, 0xff'ff'ff'e0, 0xff'ff'ff'f0, 0xff'ff'ff'f8,
        0xff'ff'ff'fc,  0xff'ff'ff'fe, 0xff'ff'ff'ff};
    char *slash_ptr{std::strchr(ip, '/')};
    *slash_ptr = '\0';
    std::uint32_t mask{mask_1[std::strtoll(slash_ptr + 1, nullptr, 10)]};
    std::uint32_t prefix{parser_ip_str(ip) & mask};
    return {prefix, prefix + ~mask};
}

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(header) == 12);

RouterBase *create_router_object() { return new Router; }

void Router::packet_dv(char *packet)
{
    std::size_t dv_length{m_dv_map.size()};
    reinterpret_cast<header *>(packet)->make_header(m_id, dv_length, header_type::dv,
                                                    sizeof(dv_table_entry) * dv_length);
    std::ranges::copy(
        std::views::transform(
            m_dv_map,
            [](auto p) {
                return dv_table_entry{p.first, p.second.distance, p.second.next};
            }),
        reinterpret_cast<dv_table_entry *>(packet + sizeof(header)));
}

void Router::release_nat(char *cmd_arg)
{
    if (auto iter{m_nat_map.find(parser_ip_str(cmd_arg))}; iter != m_nat_map.end())
    {
        m_available_addrs.push_back(iter->second);
        m_reverse_nat_map.erase(iter->second);
        m_nat_map.erase(iter);
    }
}

void Router::port_value_change(char *cmd_arg)
{
    char *tmp;
    int port{static_cast<int>(std::strtol(cmd_arg, &tmp, 10))};
    int value{static_cast<int>(std::strtol(tmp + 1, nullptr, 10))};
    if (value == -1)
    {
        m_port_value[port] = -1;
        std::ranges::for_each(m_dv_map,
                              [port](auto &p)
                              {
                                  if (p.second.port == port)
                                      p.second.distance = -1;
                              });
    }
    else if (m_port_value[port] == -1)
        m_port_value[port] = value;
    else
    {
        int difference{value - m_port_value[port]};
        m_port_value[port] = value;
        std::ranges::for_each(m_dv_map,
                              [port, difference](auto &p)
                              {
                                  if (p.second.port == port && p.second.distance != -1)
                                      p.second.distance += difference;
                              });
    }
}
void Router::add_host(char *cmd_arg)
{
    char *tmp;
    int port{static_cast<int>(std::strtol(cmd_arg, &tmp, 10))};
    std::uint32_t ip{parser_ip_str(tmp + 1)};
    m_dv_map.insert({ip, {0, port, 0}});
    m_port_value[port] = 0;
}
void Router::block(char *cmd_arg) { m_block.insert(parser_ip_str(cmd_arg)); }
void Router::unblock(char *cmd_arg) { m_block.erase(parser_ip_str(cmd_arg)); }

int Router::process_data_packet(int in_port, char *packet)
{
    header *header_ptr{reinterpret_cast<header *>(packet)};
    std::uint32_t src{header_ptr->get_src()}, dst{header_ptr->get_dst()};
    if (m_block.contains(src))
        return -1;
    if (in_port == m_ex_port)
    {
        auto dst_nat_iter{m_reverse_nat_map.find(dst)};
        if (dst_nat_iter == m_reverse_nat_map.end())
            return -1;
        std::uint32_t new_dst{dst_nat_iter->second};
        header_ptr->set_dst(new_dst);
        auto dst_port_iter{m_dv_map.find(new_dst)};
        if (dst_port_iter == m_dv_map.end() || dst_port_iter->second.distance == -1)
            return 1;
        return dst_port_iter->second.port;
    }

    auto dst_port_iter{m_dv_map.find(dst)};
    if (dst_port_iter == m_dv_map.end() || dst_port_iter->second.distance == -1)
        return 1;

    if (dst_port_iter->second.port == m_ex_port)
    {
        auto src_nat_iter{m_nat_map.find(src)};
        std::uint32_t new_src;
        if (src_nat_iter != m_nat_map.end())
            new_src = src_nat_iter->second;
        else
        {
            if (m_available_addrs.empty())
                return -1;
            new_src = m_available_addrs.back();
            m_available_addrs.pop_back();
            m_nat_map.insert({src, new_src});
            m_reverse_nat_map.insert({new_src, src});
        }
        header_ptr->set_src(new_src);
    }
    return dst_port_iter->second.port;
}

int Router::process_control_packet(int in_port, char *packet)
{
    header *header_ptr{reinterpret_cast<header *>(packet)};
    char *payload_ptr{packet + sizeof(header)};
    payload_ptr[header_ptr->get_length()] = '\0';
    switch (*payload_ptr)
    {
    case '2':
        port_value_change(payload_ptr + 2);
    case '0':
        packet_dv(packet);
        return 0;
    case '1':
        release_nat(payload_ptr + 2);
        break;
    case '3':
        add_host(payload_ptr + 2);
        break;
    case '5':
        block(payload_ptr + 2);
        break;
    case '6':
        unblock(payload_ptr + 2);
        break;
    }
    return -1;
}

int Router::process_dv_packet(int in_port, char *packet)
{
    header *dv_header{reinterpret_cast<header *>(packet)};
    std::uint32_t id{dv_header->get_src()}, dv_length{dv_header->get_dst()};
    std::span<dv_table_entry> dv_table(
        reinterpret_cast<dv_table_entry *>(packet + sizeof(header)), dv_length);

    bool change{false};
    int port_value{m_port_value[in_port]};
    for (auto [ip, distance, next] : dv_table)
    {
        if (next != m_id)
        {
            auto iter{m_dv_map.find(ip)};
            if (distance == -1)
            {
                if (iter != m_dv_map.end() && iter->second.port == in_port)
                {
                    iter->second.distance = -1;
                    change = true;
                }
            }

            else if (iter == m_dv_map.end())
            {
                m_dv_map.insert({ip, {distance + port_value, in_port, id}});
                change = true;
            }
            else if (distance + port_value < iter->second.distance ||
                     iter->second.distance == -1)
            {
                iter->second.distance = distance + port_value;
                iter->second.port = in_port;
                iter->second.next = id;
                change = true;
            }
        }
    }

    if (change)
    {
        packet_dv(packet);
        return 0;
    }

    return -1;
}

void Router::router_init(int port_num, int external_port, char *external_addr,
                         char *available_addr)
{
    static std::uint32_t id{0};
    id++;
    m_id = id;

    m_port_num = port_num;
    m_ex_port = external_port;
    m_port_value.assign(port_num + 1, -1);
    m_port_value[0] = 0;
    m_port_value[1] = 0;
    if (m_ex_port != 0)
    {
        m_port_value[m_ex_port] = 0;
        auto [ex_ip_start, ex_ip_end]{parser_ip_range(external_addr)};
        for (auto ip : std::views::iota(ex_ip_start, ex_ip_end + 1))
            m_dv_map.insert({ip, {0, m_ex_port, 0}});
        m_available_addrs.reserve(256);
        auto [available_ip_start, available_ip_end]{parser_ip_range(available_addr)};
        for (auto ip : std::views::iota(available_ip_start, available_ip_end + 1))
            m_available_addrs.push_back(ip);
    }
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
