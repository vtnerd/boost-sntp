#include <boost/range/algorithm/count.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/test/minimal.hpp>
#include <cstdint>
#include <limits>

#include "conversion.hpp"
#include "timestamp.hpp"

namespace
{
    inline std::uint32_t get_last_bit(const std::uint32_t value)
    {
        return value & sntp::to_ulong(0x01);
    }

    inline std::uint32_t ignore_last_bit(const std::uint32_t value)
    {
        return value & sntp::to_ulong(0xFFFFFFFE);
    }

    inline std::uint32_t get_first_bit(const std::uint32_t value)
    {
        return value & sntp::to_ulong(0x10000000);
    }

    inline std::uint32_t ignore_first_bit(const std::uint32_t value)
    {
        return value & sntp::to_ulong(0xEFFFFFFF);
    }

    inline std::uint32_t ignore_fractional_rounding(const std::uint32_t value)
    {
        return value & sntp::to_ulong(0xFFFF0000);
    }

    auto make_range(const sntp::timestamp& time)
    {
        return boost::make_iterator_range(
            reinterpret_cast<const std::uint8_t*>(&time),
            reinterpret_cast<const std::uint8_t*>(&time) + sizeof(time));
    }

    auto get_values(const sntp::timestamp& time)
    {
        BOOST_REQUIRE(sizeof(time) == sizeof(std::uint32_t) * 2);

        const auto range = make_range(time);
        std::uint32_t seconds = 0;
        std::uint32_t fractional = 0;

        std::memcpy(&seconds, range.begin(), sizeof(seconds));
        std::memcpy(
            &fractional, range.begin() + sizeof(seconds), sizeof(fractional));

        return std::make_pair(seconds, fractional);
    }

    auto make_timestamp(const std::pair<std::uint32_t, std::uint32_t>& values)
    {
        sntp::timestamp time;
        std::memcpy(&time, &values.first, sizeof(values.first));
        std::memcpy(
            reinterpret_cast<boost::uint8_t*>(&time) + sizeof(values.first),
            &values.second,
            sizeof(values.second));
        return time;
    }

    void check_timestamp(
        const sntp::timestamp& time,
        const std::uint32_t seconds,
        const std::uint32_t fractional)
    {
        const auto compare_values = get_values(time);
        BOOST_CHECK(compare_values.first == sntp::to_ulong(seconds));
        BOOST_CHECK(ignore_fractional_rounding(compare_values.second) ==
                    ignore_fractional_rounding(sntp::to_ulong(fractional)));
    }
}

int test_main(int, char**)
{
    {
        const sntp::timestamp::precision precise;
        BOOST_CHECK(sntp::timestamp::precision::significant_bits() == 20);
        BOOST_CHECK(sizeof(precise) == sizeof(std::int8_t));
        BOOST_CHECK(
            *reinterpret_cast<const std::int8_t*>(&precise) == -20);
    }
    {
        const sntp::timestamp time;
        BOOST_CHECK(!time.from_server());
        BOOST_CHECK(
            boost::range::count(make_range(time), 0) == sizeof(time));
    }
    {
        const sntp::timestamp time = sntp::timestamp::now();
        BOOST_CHECK(time.from_server());

        // change crypto bit
        auto values = get_values(time);
        values.second = ~(get_last_bit(values.second));

        const sntp::timestamp modified_time = make_timestamp(values);
        const auto modified_values = get_values(modified_time);

        BOOST_CHECK(!modified_time.from_server());
        BOOST_CHECK(modified_values.first == values.first);
        BOOST_CHECK(ignore_last_bit(modified_values.second) ==
                    ignore_last_bit(values.second));
    }
    {
        const sntp::timestamp time = sntp::timestamp::now();
        BOOST_CHECK(time.from_server());

        // change fractional bit
        auto values = get_values(time);
        values.second = ~(get_first_bit(values.second));

        const sntp::timestamp modified_time = make_timestamp(values);
        const auto modified_values = get_values(modified_time);

        BOOST_CHECK(!modified_time.from_server());
        BOOST_CHECK(modified_values.first == values.first);
        BOOST_CHECK(ignore_first_bit(modified_values.second) ==
                    ignore_first_bit(values.second));
    }
    {
        const sntp::timestamp time(boost::posix_time::seconds(0));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, 0, 0);
    }
    {
        const sntp::timestamp time(boost::posix_time::seconds(1));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, 1, 0);
    }
    {
        const sntp::timestamp time(boost::posix_time::seconds(-1));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, -1, 0);
    }
    {
        const sntp::timestamp time(
            (boost::posix_time::seconds(
                std::uint32_t(std::numeric_limits<long>::max()))));
        BOOST_CHECK(time.from_server());
        check_timestamp(
            time, std::uint32_t(std::numeric_limits<long>::max()), 0);
    }
    {
        const sntp::timestamp time(
            (boost::posix_time::seconds(
                std::uint32_t(std::numeric_limits<long>::min()))));
        BOOST_CHECK(time.from_server());
        check_timestamp(
            time, std::uint32_t(std::numeric_limits<long>::min()), 0);
    }
    {
        const sntp::timestamp time(boost::posix_time::microseconds(100));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, 0, 429496);
    }
    {
        const sntp::timestamp time(boost::posix_time::microseconds(-100));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, -1, 4294537799);
    }
    {
        const sntp::timestamp time(boost::posix_time::milliseconds(999));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, 0, 4290672328);
    }
    {
        const sntp::timestamp time(boost::posix_time::milliseconds(-999));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, -1, 4294967);
    }
    {
        const sntp::timestamp time(
            boost::posix_time::seconds(100) +
            boost::posix_time::microseconds(560));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, 100, 2405181);
    }
    {
        const sntp::timestamp time(
            boost::posix_time::seconds(-100) +
            boost::posix_time::microseconds(-560));
        BOOST_CHECK(time.from_server());
        check_timestamp(time, -101, 4292562114);
    }

    return 0;
}
