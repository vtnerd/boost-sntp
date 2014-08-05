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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <complex>
#include <limits>

#include "conversion.hpp"

namespace sntp
{
    namespace
    {
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
	const std::uint32_t fractional = 
	    std::abs(
		(time_since_epoch - boost::posix_time::seconds(time_since_epoch.total_seconds())).total_microseconds());

	timestamp current_time;
	current_time.seconds_ = to_ulong(seconds_since_epoch);
	current_time.fractional_ = to_ulong(fractional);
	return current_time;
    }
}
