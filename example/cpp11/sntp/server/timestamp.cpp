//
// timestamp.cpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "timestamp.hpp"

#include <array>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cmath>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <complex>
#include <limits>

#include "conversion.hpp"

namespace sntp
{
    namespace
    {
	// Generates a randm 128-bit value on construction
	class RandomString
	{
	public:

	    RandomString() :
		random_()
	    {
		CryptoPP::AutoSeededX917RNG<CryptoPP::AES> random_generator;
		random_generator.GenerateBlock(random_.data(), random_.size());
	    }

	    const std::array<std::uint8_t, 128>& get_random_string() const
	    {
		return random_;
	    }

	private:

	    std::array<std::uint8_t, 128> random_;
	};

	const RandomString random_data;
	const double fractional_ratio = std::pow(2, 32) / std::pow(10, 6);

	// total_seconds returns a long, whose type is _at least_ a 32-bit
	// signed integer. Thus, total_seconds() could have an undefined
	// value if total_seconds() exceeds a 32-bit signed integer. Mitigate
	// this by bumping the epoch to the next rollover event, but do so
	// carefully since posix_time::second also uses type long.
	const boost::posix_time::ptime epoch(
	    boost::gregorian::date(1900, 1, 1),
	    boost::posix_time::seconds(std::numeric_limits<std::int32_t>::max()) +
	    boost::posix_time::seconds(std::numeric_limits<std::int32_t>::max()) +
	    boost::posix_time::seconds(1));

	// ensure that the the expression above == uint32 max
	static_assert(
	    (
		(std::uint32_t(std::numeric_limits<std::int32_t>::max()) * 2) + 1 ==
		std::numeric_limits<std::uint32_t>::max()),
	    "unexpected int32::max value");

	// ensure int32 max does not exceed long max
	static_assert(
	    std::numeric_limits<std::int32_t>::max() <= std::numeric_limits<long>::max(),
	    "unexpected long size");
    }

    timestamp timestamp::now()
    {
	const auto time_since_epoch =
	    boost::posix_time::microsec_clock::universal_time() - epoch;

	// NTP seconds is modulus operation since 1900. C++ integer conversion
	// rules to an unsigned type are also modulus.
	const std::uint32_t seconds_since_epoch = time_since_epoch.total_seconds();
	const std::uint32_t microsecond_precision =
	    std::abs(
		(time_since_epoch - boost::posix_time::seconds(time_since_epoch.total_seconds())).total_microseconds());

	timestamp current_time;
	current_time.seconds_ = to_ulong(seconds_since_epoch);
	current_time.fractional_ = to_ulong(std::uint32_t(microsecond_precision * fractional_ratio));
	return current_time;
    }
}
