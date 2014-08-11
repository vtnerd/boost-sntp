//
// conversion.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef CONVERSION_HPP
#define CONVERSION_HPP

#include <boost/asio/detail/socket_ops.hpp>
#include <cstdint>

namespace sntp
{
    inline std::uint32_t to_ulong(const std::uint32_t convert)
    {
        return boost::asio::detail::socket_ops::host_to_network_long(convert);
    }
}

#endif // CONVERSION_HPP
