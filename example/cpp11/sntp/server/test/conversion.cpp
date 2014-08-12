#include <boost/test/minimal.hpp>

#include "conversion.hpp"

int test_main(int, char**)
{
    BOOST_CHECK(sntp::to_ulong(0xDEADBEEF) == sntp::to_ulong(0xDEADBEEF));
    // let fail on big-endian for now
    BOOST_CHECK(sntp::to_ulong(0xDEADBEEF) == 0xEFBEADDE); 
    return 0;
}
