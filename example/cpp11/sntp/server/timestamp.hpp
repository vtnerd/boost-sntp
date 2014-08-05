//
// timestamp.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
// 
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef TIMESTAMP_HPP
#define TIMESTAMP_HPP

#include <cstdint>
#include <type_traits>

namespace sntp
{
    class timestamp
    {
    public:

	// Represents server precision, currently a constant
	class precision
	{
	public:

	    static precision get()
	    {
		precision constant;
		constant.precision_ = -19;
		return constant;
	    }
	    
	private:
	    std::int8_t precision_;
	};

	// Retrieve the current timestamp
	static timestamp now();

    private:

	std::uint32_t seconds_;
	std::uint32_t fractional_;
    };

    static_assert(sizeof(timestamp) == 8, "padding added to timestamp fields");
    static_assert(sizeof(timestamp::precision) == 1, "padding added to precision fields");
    static_assert(std::is_pod<timestamp>::value, "timestamp must be pod");
    static_assert(std::is_pod<timestamp::precision>::value, "timestamp precision must be pod");
}

#endif // TIMESTAMP_HPP