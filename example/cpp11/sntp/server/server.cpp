//
// server.cpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2014 Lee Clagett (code at leeclagett dot com)
// 
// Distributed under the Boost Software License, Version 1.0. (See accompanying)
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <cstdint>
#include <memory>

#include "packet.hpp"

namespace
{
    const std::uint16_t ntp_port = 123;

    struct ntp_server
    {
    public:
	
	ntp_server(boost::asio::io_service& service) :
	    socket_(service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), ntp_port)),
	    remote_endpoint_()
	{
	    wait_for_request();
	}
	
	void wait_for_request()
	{
	    const auto packet = sntp::packet::allocate();
	    socket_.async_receive_from(
		packet->get_receive_buffer(),
		remote_endpoint_,
		(
		    [this, packet]
		    (const boost::system::error_code& error, const std::size_t bytes_received)
		    { 
			if (!error && sntp::packet::minimum_packet_size() <= bytes_received)
			{
			    this->send_response(packet);
			}
			this->wait_for_request();
		    }));
	}

    private:

	void send_response(const std::shared_ptr<sntp::packet>& response_packet)
	{
	    // make sure to keep shared_ptr to packet active while sending data.
	    response_packet->fill_server_values();
	    socket_.async_send_to(
		response_packet->get_send_buffer(),
		remote_endpoint_,
		[response_packet](const boost::system::error_code&, const std::size_t){});
	}

    private:

	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::endpoint remote_endpoint_;
    };
}

int main()
{
    boost::asio::io_service service;
    ntp_server server(service);
    service.run();

    return 0;
}
