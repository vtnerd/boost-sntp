//
// packet.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef PACKET_HPP
#define PACKET_HPP

#include <array>
#include <boost/asio/buffer.hpp>
#include <cstdint>
#include <memory>
#include <type_traits>

#include "timestamp.hpp"

namespace sntp
{
    class packet
    {
    public:

        // Allocate a zero initialized NTP packet
        static std::shared_ptr<packet> allocate()
        {
            return std::make_shared<packet>();
        }

        // Minimum size for a NTP packet
        static constexpr std::size_t minimum_packet_size()
        {
            return sizeof(packet) - sizeof(packet::key_identifier_) - sizeof(packet::digest_);
        }

        // zero initialize a NTP packet
        packet();

        // Get the buffer for reading
        auto get_receive_buffer()
        {
            return boost::asio::buffer(this, sizeof(packet));
        }

        // Get the buffer for writing
        auto get_send_buffer() const
        {
            return boost::asio::buffer(this, minimum_packet_size());
        }

        // Update packet with values needed by client. False is returned
        // if packet appears to have come from server.
        bool fill_server_values();

    private:

        std::uint8_t flags_;

        std::uint8_t stratum_;

        std::uint8_t poll_;

        timestamp::precision precision_;

        std::uint32_t delay_;

        std::uint32_t dispersion_;

        std::array<std::uint8_t, 4> identifier_;

        timestamp reference_;

        timestamp originate_;

        timestamp receive_;

        timestamp transmit_;

        std::uint32_t key_identifier_;

        std::array<std::uint8_t, 16> digest_;
    };

//    static_assert(std::is_trivially_copyable<packet>::value, "packet must be pod");
    static_assert(packet::minimum_packet_size() <= sizeof(packet), "bad min packet size");
    static_assert(sizeof(packet) == sizeof(std::uint32_t) * 17, "invalid packet size");
}

#endif // PACKET_HPP
