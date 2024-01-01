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

static bool operator<(const ex_map_key &lhs, const ex_map_key &rhs)
{
    return lhs.end < rhs.start;
}

static bool operator<(const ex_map_key &lhs, const std::uint32_t &rhs)
{
    return lhs.end < rhs;
}

static bool operator<(const std::uint32_t &lhs, const ex_map_key &rhs)
{
    return lhs < rhs.start;
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

static bool is_ex_ip(std::uint32_t ip) { return (ip >> 24) ^ 0x0A; }

RouterBase *create_router_object() { return new Router; }

void Router::packet_dv(char *packet)
{
    std::uint16_t dv_size{static_cast<std::uint16_t>(m_dv_map.size())};
    std::uint16_t ex_dv_size{static_cast<std::uint16_t>(m_ex_dv_map.size())};

    header *header_ptr{reinterpret_cast<header *>(packet)};
    header_ptr->make_header(0, 0, header_type::dv,
                            dv_size * sizeof(dv_table_entry) +
                                ex_dv_size * sizeof(ex_dv_table_entry) +
                                2u * sizeof(std::uint16_t));
    if (dv_size * sizeof(dv_table_entry) + ex_dv_size * sizeof(ex_dv_table_entry) +
            2u * sizeof(std::uint16_t) + sizeof(header) >
        16384)
        log_debug("Too long");
    char *payload_ptr{packet + sizeof(header)};
    *reinterpret_cast<std::uint16_t *>(payload_ptr) = dv_size;
    *reinterpret_cast<std::uint16_t *>(payload_ptr + sizeof(std::uint16_t)) = ex_dv_size;
    dv_table_entry *dv_table_ptr{
        reinterpret_cast<dv_table_entry *>(payload_ptr + 2u * sizeof(std::uint16_t))};
    ex_dv_table_entry *ex_dv_table_ptr{reinterpret_cast<ex_dv_table_entry *>(
        payload_ptr + dv_size * sizeof(dv_table_entry) + 2u * sizeof(std::uint16_t))};
    std::size_t i{0};
    for (auto &p : m_dv_map)
    {
        dv_table_ptr[i].ip = p.first;
        dv_table_ptr[i].distance = p.second.distance;
        i++;
    }
    i = 0;
    for (auto &p : m_ex_dv_map)
    {
        ex_dv_table_ptr[i].ip_range = p.first;
        ex_dv_table_ptr[i].distance = p.second.distance;
        i++;
    }
}

void Router::release_nat(char *cmd_arg)
{
    std::uint32_t ip{parser_ip_str(cmd_arg)};
    auto iter{m_nat_map.find(ip)};
    if (iter != m_nat_map.end())
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
        std::erase_if(m_dv_map, [port](std::pair<const std::uint32_t, map_entry> &p)
                      { return p.second.port == port; });
        std::erase_if(m_ex_dv_map, [port](std::pair<const ex_map_key, map_entry> &p)
                      { return p.second.port == port; });
    }
    else
    {
        int difference{value - m_port_value[port]};
        m_port_value[port] = value;
        std::ranges::for_each(
            m_dv_map,
            [port, difference](std::pair<const std::uint32_t, map_entry> &p)
            {
                if (p.second.port == port)
                    p.second.distance += difference;
            });
        std::ranges::for_each(
            m_ex_dv_map,
            [port, difference](std::pair<const ex_map_key, map_entry> &p)
            {
                if (p.second.port == port)
                    p.second.distance += difference;
            });
    }
}
void Router::add_host(char *cmd_arg)
{
    char *tmp;
    int port{static_cast<int>(std::strtol(cmd_arg, &tmp, 10))};
    std::uint32_t ip{parser_ip_str(tmp + 1)};
    m_dv_map.insert({ip, {0, port}});
    m_port_value[port] = 0;
    log_debug("Add host ", port, ' ', ip);
}
void Router::block(char *cmd_arg) { m_block.insert(parser_ip_str(cmd_arg)); }
void Router::unblock(char *cmd_arg) { m_block.erase(parser_ip_str(cmd_arg)); }

int Router::process_data_packet(int in_port, char *packet)
{
    header *header_ptr{reinterpret_cast<header *>(packet)};
    std::uint32_t src{header_ptr->get_src()}, dst{header_ptr->get_dst()};
    log_debug("Data ", src, " --> ", dst);
    if (m_block.contains(src))
        return -1;
    bool src_is_ex{is_ex_ip(src)}, dst_is_ex{is_ex_ip(dst)};
    if (src_is_ex)
    {
        return -1;
    }
    else
    {
        if (dst_is_ex)
        {
            auto dst_port_iter{m_ex_dv_map.find(dst)};
            if (dst_port_iter == m_ex_dv_map.end())
                return 1;
            int port{dst_port_iter->second.port};
            if (port == m_ex_port)
            {
                auto nat_ip_iter{m_nat_map.find(src)};
                std::uint32_t new_nat_ip;
                if (nat_ip_iter != m_nat_map.end())
                    new_nat_ip = nat_ip_iter->second;
                else
                {
                    if (m_available_addrs.empty())
                        return -1;
                    new_nat_ip = m_available_addrs.back();
                    m_available_addrs.pop_back();
                    m_nat_map.insert({src, new_nat_ip});
                    m_reverse_nat_map.insert({new_nat_ip, src});
                }
                header_ptr->set_src(new_nat_ip);
            }
            return port;
        }
        else
        {
            auto dst_port_iter{m_dv_map.find(dst)};
            if (dst_port_iter == m_dv_map.end())
                return 1;
            return dst_port_iter->second.port;
        }
    }
}

int Router::process_control_packet(int in_port, char *packet)
{
    header *header_ptr{reinterpret_cast<header *>(packet)};
    char *payload_ptr{packet + sizeof(header)};
    payload_ptr[header_ptr->get_length()] = '\0';
    switch (*payload_ptr)
    {
    case '0':
        packet_dv(packet);
        return 0;
    case '1':
        release_nat(payload_ptr + 2);
        break;
    case '2':
        port_value_change(payload_ptr + 2);
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
    std::uint16_t *length{reinterpret_cast<std::uint16_t *>(packet + sizeof(header))};
    std::uint16_t dv_length{length[0]};
    std::uint16_t ex_dv_length{length[1]};
    std::span<dv_table_entry> dv_table{
        reinterpret_cast<dv_table_entry *>(packet + sizeof(header) +
                                           2u * sizeof(std::uint16_t)),
        dv_length};
    std::span<ex_dv_table_entry> ex_dv_table{
        reinterpret_cast<ex_dv_table_entry *>(packet + sizeof(header) +
                                              dv_length * sizeof(dv_table_entry) +
                                              2u * sizeof(std::uint16_t)),
        ex_dv_length};
    bool change{false};
    int port_value{m_port_value[in_port]};
    for (auto &p : dv_table)
    {
        auto dv_iter{m_dv_map.find(p.ip)};
        if (dv_iter == m_dv_map.end())
        {
            m_dv_map.insert({p.ip, {port_value + p.distance, in_port}});
            change = true;
        }
        else if (dv_iter->second.distance > p.distance + port_value)
        {
            dv_iter->second.distance = p.distance + port_value;
            dv_iter->second.port = in_port;
            change = true;
        }
    }

    for (auto &p : ex_dv_table)
    {
        auto dv_iter{m_ex_dv_map.find(p.ip_range)};
        if (dv_iter == m_ex_dv_map.end())
        {
            m_ex_dv_map.insert({p.ip_range, {port_value + p.distance, in_port}});
            change = true;
        }
        else if (dv_iter->second.distance > p.distance + port_value)
        {
            dv_iter->second.distance = p.distance + port_value;
            dv_iter->second.port = in_port;
            change = true;
        }
    }
    if (!change)
        return -1;

    packet_dv(packet);
    return 0;
}

void Router::router_init(int port_num, int external_port, char *external_addr,
                         char *available_addr)
{
    m_port_num = port_num;
    m_ex_port = external_port;
    m_port_value.assign(port_num, -1);
    m_port_value[0] = 0;
    m_port_value[1] = 0;
    if (m_ex_port != 0)
    {
        m_port_value[m_ex_port] = 0;
        auto [ex_ip_start, ex_ip_end]{parser_ip_range(external_addr)};
        m_ex_dv_map.insert({{ex_ip_start, ex_ip_end}, {0, m_ex_port}});
        m_available_addrs.reserve(256);
        auto [available_ip_start, available_ip_end]{parser_ip_range(external_addr)};
        for (auto ip : std::views::iota(available_ip_start, available_ip_end))
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
