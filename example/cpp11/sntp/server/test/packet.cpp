#include <algorithm>
#include <boost/asio/detail/socket_ops.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/range/algorithm/equal.hpp>
#include <boost/range/algorithm/fill.hpp>
#include <boost/range/counting_range.hpp>
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
#include "packet_util.hpp"

namespace
{
    using test_packet = std::array<std::uint8_t, sizeof(sntp::packet)>;

    const std::uint8_t current_version = 4;
    const std::uint8_t client_mode = 3;
    const std::uint8_t server_mode = 4;


    auto make_version_range()
    {
        // range is [0,8)
        return boost::counting_range(0, 8);
    }

    auto make_mode_range()
    {
        // range is [0,8)
        return boost::counting_range(0, 8);
    }

    auto make_range(const sntp::packet& packet)
    {
        return boost::make_iterator_range(
            reinterpret_cast<const std::uint8_t*>(&packet),
            reinterpret_cast<const std::uint8_t*>(&packet) + sizeof(packet));
    }

    // Get the range of bytes for the specified timestamp offset. Range must
    // be 8 bytes in length from the offset.
    boost::iterator_range<const std::uint8_t*>
    get_timestamp_range(
        const boost::iterator_range<const std::uint8_t*>& range,
        const std::uint32_t offset)
    {
        assert(test::sntp::total_timestamp_length <= range.size());
        assert(offset < range.size() - test::sntp::total_timestamp_length);
        return boost::make_iterator_range(
            range.begin() + offset,
            range.begin() + offset + test::sntp::total_timestamp_length);
    }

    sntp::packet make_filled_packet(
        const std::uint8_t version, const std::uint8_t mode)
    {
        sntp::packet new_packet;
        {
            test_packet buffer;
            boost::range::fill(buffer, 0xFF);
            buffer[0] = (version << 3) | mode;
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
        boost::range::copy(
            get_timestamp_range(
                original_range, test::sntp::transmit_timestamp_offset),
            expected.begin() + test::sntp::originate_timestamp_offset);

        // current timestamps are hard to calculate, so
        // copy transmit and receive (but verify transmit
        // is after receive)
        {
            BOOST_CHECK(test::sntp::receive_before_transmit(server_range));

            boost::range::copy(
                get_timestamp_range(
                    server_range, test::sntp::receive_timestamp_offset),
                expected.begin() + test::sntp::receive_timestamp_offset);

            boost::range::copy(
                get_timestamp_range(
                    server_range, test::sntp::transmit_timestamp_offset),
                expected.begin() + test::sntp::transmit_timestamp_offset);

        }

        // copy the bytes that aren't sent out (they are unmodified)
        std::copy(
            original_range.begin() + test::sntp::optional_section_offset,
            original_range.end(),
            expected.begin() + test::sntp::optional_section_offset);

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
    // try every version
    {
        for (std::uint8_t test_version : make_version_range())
        {
            sntp::packet packet =
                make_filled_packet(test_version, client_mode);

            const sntp::packet original = packet;

            if (test_version == current_version)
            {
                BOOST_CHECK(packet.fill_server_values());
                verify_packet(make_test_packet(original, packet), packet);
            }
            else
            {
                BOOST_CHECK(!packet.fill_server_values());
                BOOST_CHECK(
                    boost::range::equal(
                        make_range(original), make_range(packet)));
            }

            BOOST_CHECK(!packet.fill_server_values());
        }
    }
    // try every mode
    {
        for (std::uint8_t test_mode : make_mode_range())
        {
            sntp::packet packet =
                make_filled_packet(current_version, test_mode);

            const sntp::packet original = packet;

            if (test_mode == server_mode ||
                test_mode == client_mode)
            {
                BOOST_CHECK(packet.fill_server_values());
                verify_packet(make_test_packet(original, packet), packet);
            }
            else
            {
                BOOST_CHECK(!packet.fill_server_values());
                BOOST_CHECK(
                    boost::range::equal(
                        make_range(original), make_range(packet)));
            }

            BOOST_CHECK(!packet.fill_server_values());
        }
    }
    {
        // alter last byte of crypto string
        sntp::packet packet = make_filled_packet(current_version, server_mode);
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
        sntp::packet packet = make_filled_packet(current_version, server_mode);
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
