#include <boost/range/algorithm/count.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/test/minimal.hpp>
#include <cstdint>

#include "conversion.hpp"
#include "timestamp.hpp"

namespace 
{
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
	values.second = ~(values.first & sntp::to_ulong(0x01));

	const sntp::timestamp modified_time = make_timestamp(values);
	const auto modified_values = get_values(modified_time);

	BOOST_CHECK(!modified_time.from_server());
	BOOST_CHECK(modified_values.first == values.first);
	BOOST_CHECK((modified_values.second & sntp::to_ulong(0xFFFFFFFE)) == 
		    (values.second & sntp::to_ulong(0xFFFFFFFE)));
    }
    {
	const sntp::timestamp time = sntp::timestamp::now();
	BOOST_CHECK(time.from_server());

	// change fractional bit
	auto values = get_values(time);
	values.second = ~(values.first & sntp::to_ulong(0x10000000));

	const sntp::timestamp modified_time = make_timestamp(values);
	const auto modified_values = get_values(modified_time);

	BOOST_CHECK(!modified_time.from_server());
	BOOST_CHECK(modified_values.first == values.first);
	BOOST_CHECK((modified_values.second & sntp::to_ulong(0xEFFFFFFF)) == 
		    (values.second & sntp::to_ulong(0xEFFFFFFF)));
    }

    return 0;
}
