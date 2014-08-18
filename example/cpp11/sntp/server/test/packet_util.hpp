#ifndef PACKET_UTIL_HPP
#define PACKET_UTIL_HPP

namespace test
{
    namespace sntp
    {
	const std::uint32_t significant_fraction_mask = 0xFFFFF000;
	const std::uint8_t total_timestamp_length = 8;

	const std::uint8_t originate_timestamp_offset = 24;
	const std::uint8_t originate_seconds_offset = originate_timestamp_offset;
	const std::uint8_t originate_fractional_offset = originate_seconds_offset + 4;

	const std::uint8_t receive_timestamp_offset = 32;
	const std::uint8_t receive_seconds_offset = receive_timestamp_offset;
	const std::uint8_t receive_fractional_offset = receive_seconds_offset + 4;

	const std::uint8_t transmit_timestamp_offset = 40;
	const std::uint8_t transmit_seconds_offset = transmit_timestamp_offset;
	const std::uint8_t transmit_fractional_offset = transmit_seconds_offset + 4;

	const std::uint8_t optional_section_offset = 48;


	// Take a fractional value, and ignore the crypto string portion
	// The function is "dumb" and assumes -20 currently
	inline constexpr std::uint32_t ignore_crypto_string(const std::uint32_t value)
	{
	    return value & significant_fraction_mask;
	}

	// Extract an uint32 from a range of bytes. Range must be long enough
	// from offset + 4.
	template<typename Range>
	inline
	std::uint32_t extract_ulong(const Range& range, const std::uint8_t offset)
	{
	    assert(sizeof(std::uint32_t) <= range.size());
	    assert(offset <= range.size() - sizeof(std::uint32_t));
	    
	    std::uint32_t value = 0;
	    std::memcpy(&value, range.begin() + offset, sizeof(value));
	    return boost::asio::detail::socket_ops::network_to_host_long(value);
	}

	// The range must be a sntp packet. Return true if the receive timestamp
	// is after the send timestamp.
	template<typename Range>
	inline
	bool receive_before_transmit(const Range& range)
	{
	    assert(sizeof(std::uint32_t) + transmit_fractional_offset <= range.size());
	    const std::uint32_t receive_seconds =
                extract_ulong(range, receive_seconds_offset);
            const std::uint32_t receive_fractional =
                extract_ulong(range, receive_fractional_offset);
            const std::uint32_t transmit_seconds =
                extract_ulong(range, transmit_seconds_offset);
            const std::uint32_t transmit_fractional =
                extract_ulong(range, transmit_fractional_offset);

	    if (receive_seconds <= transmit_seconds)
	    {
		return 
		    ignore_crypto_string(receive_fractional) <=
		    ignore_crypto_string(transmit_fractional)
		    ||
		    receive_seconds < transmit_seconds;
	    }

	    return false;
	}
    }
}

#endif // PACKET_UTIL_HPP
