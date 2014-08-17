#include <algorithm>
#include <boost/asio/detail/socket_ops.hpp>
#include <boost/range/algorithm/equal.hpp>
#include <boost/range/algorithm/fill.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/spirit/include/karma_char.hpp>
#include <boost/spirit/include/karma_eol.hpp>
#include <boost/spirit/include/karma_generate_attr.hpp>
#include <boost/spirit/include/karma_list.hpp>
#include <boost/spirit/include/karma_right_alignment.hpp>
#include <boost/spirit/include/karma_sequence.hpp>
#include <boost/spirit/include/karma_string.hpp>
#include <boost/spirit/include/karma_uint.hpp>
#include <boost/test/minimal.hpp>
#include <cstdint>

#include "packet.hpp"

namespace
{
    using test_packet = std::array<std::uint8_t, sizeof(sntp::packet)>;

    constexpr std::uint32_t ignore_crypto_string(const std::uint32_t value)
    {
        return value & 0xFFFFF000;
    }

    std::uint32_t extract_ulong(
        const boost::iterator_range<const boost::uint8_t*>& range,
        const std::uint8_t offset)
    {
        assert(sizeof(std::uint32_t) <= range.size());
        assert(offset < range.size() - sizeof(std::uint32_t));

        std::uint32_t value = 0;
        std::memcpy(&value, range.begin() + offset, sizeof(value));
        return boost::asio::detail::socket_ops::network_to_host_long(value);
    }

    auto make_range(const sntp::packet& packet)
    {
        return boost::make_iterator_range(
            reinterpret_cast<const std::uint8_t*>(&packet),
            reinterpret_cast<const std::uint8_t*>(&packet) + sizeof(packet));
    }

    sntp::packet make_filled_packet()
    {
        sntp::packet new_packet;
        {
            test_packet buffer;
            boost::range::fill(buffer, 0xFF);
            buffer[0] = 0x20; // version must be set
            static_assert(
                sizeof(test_packet) == buffer.size(),
                "invalid packet size");
            std::memcpy(&new_packet, buffer.data(), buffer.size());
        }
        return new_packet;
    }

    test_packet make_default_test_packet()
    {
        test_packet new_packet = {{0}};
        new_packet[0] = 0x24; // version and server mode
        new_packet[3] = 0xEC; // precision
        return new_packet;
    }

    // original == timestamp before fill_server_values() call
    // server == timestamp after fill_server_values() call
    test_packet make_test_packet(
        const sntp::packet& original,
        const sntp::packet& server)
    {
        const auto original_range = make_range(original);
        const auto server_range = make_range(server);
        test_packet expected = make_default_test_packet();

        static_assert(
            sizeof(original) == expected.size(),
            "test packet is invalid size");

        expected[0] = 0xE4;
        expected[1] = 0x01;
        expected[2] = 0x06;
        expected[3] = 0xEC;
        expected[12] = 'L';
        expected[13] = 'O';
        expected[14] = 'C';
        expected[15] = 'L';

        // original receive timestamp should
        // be moved to originate timestamp
        std::copy(
            original_range.begin() + 40,
            original_range.begin() + 48,
            expected.begin() + 24);

        // current timestamps are hard to calculate, so
        // copy transmit and receive (but verify transmit
        // is after receive)
        {
            const std::uint32_t receive_seconds =
                extract_ulong(server_range, 32);
            const std::uint32_t receive_fractional =
                extract_ulong(server_range, 36);
            const std::uint32_t transmit_seconds =
                extract_ulong(server_range, 40);
            const std::uint32_t transmit_fractional =
                extract_ulong(server_range, 44);

            BOOST_CHECK(receive_seconds <= transmit_seconds);
            BOOST_CHECK(
                ignore_crypto_string(receive_fractional) <=
                ignore_crypto_string(transmit_fractional)
                ||
                receive_seconds < transmit_seconds);

            std::copy(
                server_range.begin() + 32,
                server_range.begin() + 48,
                expected.begin() + 32);
        }

        // copy the bytes that aren't sent out (they are unmodified)
        std::copy(
            original_range.begin() + 48,
            original_range.end(),
            expected.begin() + 48);

        return expected;
    }

    void verify_packet(
        const test_packet& expected, sntp::packet& actual)
    {
        const auto packet_range = make_range(actual);
        const auto receive_buffer = actual.get_receive_buffer();
        const auto send_buffer = actual.get_send_buffer();

        BOOST_CHECK(packet_range.size() == sizeof(actual));
        BOOST_CHECK(
            boost::asio::buffer_size(receive_buffer) == packet_range.size());
        BOOST_CHECK(
            boost::asio::buffer_size(send_buffer) ==
            sntp::packet::minimum_packet_size());

        BOOST_CHECK(
            boost::asio::buffer_cast<const std::uint8_t*>(receive_buffer) ==
            packet_range.begin());
        BOOST_CHECK(
            boost::asio::buffer_cast<const std::uint8_t*>(send_buffer) ==
            packet_range.begin());

        if (!boost::range::equal(expected, packet_range))
        {
            namespace karma = boost::spirit::karma;

            const auto bytes = (karma::right_align(2, '0')[karma::hex]) % " ";

            std::string error;
            karma::generate(
                std::back_inserter(error),
                (
                    karma::eol << // line up each line visually
                    "Expected: {" << bytes << "}" << karma::eol <<
                    "Actual:   {" << bytes << "}" << karma::eol),
                expected,
                packet_range);

            BOOST_FAIL(error.c_str());
        }
    }
}

int test_main(int, char**)
{
    {
        sntp::packet packet;
        verify_packet(make_default_test_packet(), packet);

        const sntp::packet original = packet;
        BOOST_CHECK(packet.fill_server_values());
        verify_packet(make_test_packet(original, packet), packet);

        BOOST_CHECK(!packet.fill_server_values());
    }
    {
        sntp::packet packet = make_filled_packet();

        const sntp::packet original = packet;
        BOOST_CHECK(packet.fill_server_values());
        verify_packet(make_test_packet(original, packet), packet);

        BOOST_CHECK(!packet.fill_server_values());
    }
    {
        // alter last byte of crypto string
        sntp::packet packet = make_filled_packet();
        BOOST_CHECK(packet.fill_server_values());
        {
            test_packet bad_crypto_string;
            static_assert(
                sizeof(packet) == bad_crypto_string.size(),
                "bad packet size");

            std::memcpy(
                bad_crypto_string.data(), &packet, bad_crypto_string.size());
            bad_crypto_string[47] = ~bad_crypto_string[47];
            std::memcpy(
                &packet, bad_crypto_string.data(), bad_crypto_string.size());
        }
        const sntp::packet original = packet;
        BOOST_CHECK(packet.fill_server_values());
        verify_packet(make_test_packet(original, packet), packet);

        BOOST_CHECK(!packet.fill_server_values());
    }
    {
        // alter first byte of fractional
        sntp::packet packet = make_filled_packet();
        BOOST_CHECK(packet.fill_server_values());
        {
            test_packet bad_crypto_string;
            static_assert(
                sizeof(packet) == bad_crypto_string.size(),
                "bad packet size");

            std::memcpy(
                bad_crypto_string.data(), &packet, bad_crypto_string.size());
            bad_crypto_string[40] = ~bad_crypto_string[40];
            std::memcpy(
                &packet, bad_crypto_string.data(), bad_crypto_string.size());
        }
        const sntp::packet original = packet;
        BOOST_CHECK(packet.fill_server_values());
        verify_packet(make_test_packet(original, packet), packet);

        BOOST_CHECK(!packet.fill_server_values());
    }
    return 0;
}
