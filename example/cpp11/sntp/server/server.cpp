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
#include <boost/spirit/include/qi_eoi.hpp>
#include <boost/spirit/include/qi_parse.hpp>
#include <boost/spirit/include/qi_sequence.hpp>
#include <boost/spirit/include/qi_uint.hpp>
#include <cstdint>
#include <iostream>
#include <memory>

#include "packet.hpp"

namespace
{
    struct ntp_server
    {
    public:

        ntp_server(boost::asio::io_service& service, const std::uint16_t port) :
            socket_(
                service,
                boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)),
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
            if (response_packet->fill_server_values())
            {
                // make sure to keep shared_ptr to packet active while sending data.
                socket_.async_send_to(
                    response_packet->get_send_buffer(),
                    remote_endpoint_,
                    [response_packet](const boost::system::error_code&, const std::size_t){});
            }
        }

    private:

        boost::asio::ip::udp::socket socket_;
        boost::asio::ip::udp::endpoint remote_endpoint_;
    };

    int display_option_error(const char* const error, int argc, const char** argv)
    {
        if (argc == 0)
        {
            std::cerr << "Bad program" << std::endl;
        }
        else
        {
            std::cerr << error << "\n\n" <<
                argv[0] << " [port]" << std::endl;
        }

        return EXIT_FAILURE;
    }
}

int main(int argc, const char** argv)
{
    if (argc != 2)
    {
        return display_option_error("Two arguments required", argc, argv);
    }

    std::uint16_t port = 0;
    if (!boost::spirit::qi::parse(
            argv[1],
            argv[1] + strlen(argv[1]),
            (boost::spirit::qi::ushort_ >> boost::spirit::qi::eoi),
            port))
    {
        return display_option_error("Invalid port provided", argc, argv);
    }

    try
    {
        boost::asio::io_service service;
        ntp_server server(service, port);
        service.run();
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
