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
#include <complex>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <limits>

#include "conversion.hpp"

namespace sntp
{
    namespace
    {
	// Generates a random 128-bit value on construction
	class RandomString
	{
	public:

	    RandomString() :
		random_()
	    {
		CryptoPP::AutoSeededX917RNG<CryptoPP::AES> random_generator;
		random_generator.GenerateBlock(random_.data(), random_.size());
	    }

	    const std::array<std::uint8_t, 16>& get_random_string() const
	    {
		return random_;
	    }

	private:

	    std::array<std::uint8_t, 16> random_;
	};



	// random string for detecting loops and replay attacks
	const RandomString random_data;

	// masks for bits of the timestamp that (in)significant due to accuracy
	static_assert(timestamp::precision::significant_bits() <= 64, "bad bit value");
	const std::uint32_t insignificant_mask =
	    to_ulong(
		std::numeric_limits<std::uint32_t>::max() >>
		(32 - timestamp::precision::significant_bits()));
        const std::uint32_t significant_mask = ~insignificant_mask;

	// ratio for converting microseconds to NTP fractional
	const double fractional_ratio = std::pow(2, 32) / std::pow(10, 6);

	// total_seconds returns a long, whose type is _at least_ a 32-bit
	// signed integer. Thus, total_seconds() could have an undefined
	// value if total_seconds() exceeds a 32-bit signed integer. Mitigate
	// this by bumping the epoch to the next rollover event, but do so
	// carefully since posix_time::second also uses type long.
	static_assert(
	    (
		(std::uint32_t(std::numeric_limits<std::int32_t>::max()) * 2) + 1 ==
		std::numeric_limits<std::uint32_t>::max()),
	    "unexpected int32::max value");
	static_assert(
	    std::numeric_limits<std::int32_t>::max() <= std::numeric_limits<long>::max(),
	    "unexpected long size");
	const boost::posix_time::ptime epoch(
	    boost::gregorian::date(1900, 1, 1),
	    boost::posix_time::seconds(std::numeric_limits<std::int32_t>::max()) +
	    boost::posix_time::seconds(std::numeric_limits<std::int32_t>::max()) +
	    boost::posix_time::seconds(1));
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
        current_time.generate_crypto_string();
	return current_time;
    }

    bool timestamp::from_server() const
    {
        timestamp crypto(*this);
        crypto.generate_crypto_string();
	return crypto.seconds_ == seconds_ && crypto.fractional_ == fractional_;
    }

    void timestamp::generate_crypto_string()
    {
	std::uint32_t crypto_string = 0;
        fractional_ &= significant_mask;
	{
	    std::array<std::uint8_t, CryptoPP::SHA256::DIGESTSIZE> hash_value;

            CryptoPP::SHA256 hash;
	    hash.Update(
		random_data.get_random_string().data(),
		random_data.get_random_string().size());
            hash.Update(
                reinterpret_cast<const std::uint8_t*>(&seconds_),
                sizeof(seconds_));
	    hash.Update(
		reinterpret_cast<const std::uint8_t*>(&fractional_),
		sizeof(fractional_));
	    hash.Final(hash_value.data());

	    static_assert(sizeof(crypto_string) <= hash_value.size(), "hash is too small");
	    std::memcpy(&crypto_string, hash_value.data(), sizeof(crypto_string));
	}
	crypto_string &= insignificant_mask;
	fractional_ |= crypto_string;
    }
}
