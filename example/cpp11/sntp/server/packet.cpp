//
// packet.cpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "packet.hpp"

#include <boost/range/algorithm/copy.hpp>

namespace sntp
{
    namespace
    {
        const std::uint8_t alarm_condition = 0xC0;
        const std::uint8_t version = 0x20;
        const std::uint8_t server = 0x04;

        const std::uint8_t primary_reference = 1;
        const std::uint8_t sixty_four_second_poll_interval = 6;
        const std::array<std::uint8_t, 4> uncalibrated_local_clock = {{'L', 'O', 'C', 'L'}};
    }

    packet::packet() :
        flags_(),
        stratum_(),
        poll_(),
        precision_(),
        delay_(),
        dispersion_(),
        identifier_(),
        reference_(),
        originate_(),
        receive_(),
        transmit_(),
        key_identifier_(),
        digest_()
    {
    }

    bool packet::fill_server_values()
    {
        if (!transmit_.from_server())
        {
            receive_ = timestamp::now();

            flags_ = alarm_condition | version | server;
            stratum_ = primary_reference;
            poll_ = sixty_four_second_poll_interval;
            precision_ = timestamp::precision();
            delay_ = 0;
            dispersion_ = 0;
            {
                static_assert(sizeof(identifier_) == uncalibrated_local_clock.size(), "size mismatch");
                boost::range::copy(uncalibrated_local_clock, identifier_.begin());
            }
            reference_ = timestamp();
            originate_ = transmit_;

            transmit_ = timestamp::now();
            return true;
        }

        return false;
    }
}
