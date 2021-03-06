#include <array>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/optional.hpp>
#include <boost/spirit/include/qi_eoi.hpp>
#include <boost/spirit/include/qi_parse.hpp>
#include <boost/spirit/include/qi_sequence.hpp>
#include <boost/spirit/include/qi_uint.hpp>
#include <cassert>
#include <cstdint>
#include <limits>
#include <iostream>
#include <queue>
#include <vector>

#include "packet_util.hpp"
#include "timestamp.hpp"

namespace
{
    const std::uint8_t mode_mask = 0x07;

    // constants used in test packets
    const std::uint8_t valid_version = 0x20;
    const std::uint8_t invalid_version = 0x18;
    const std::uint8_t alarm_condition = 0xC0;
    const std::uint8_t client_indicator = 0x03;
    const std::uint8_t server_indicator = 0x04;

    class sntp_packet
    {
    public:

        static const std::uint16_t packet_size = 48;
        using packet_array = std::array<std::uint8_t, packet_size>;

        sntp_packet() :
            data_(),
            range_(data_.begin(), data_.end())
        {
        }

        const packet_array& get_array() const
        {
            return data_;
        }

        packet_array& get_array()
        {
            return data_;
        }

        void shrink_buffer()
        {
            static_assert(packet_array().size() != 0, "buffer cannot be empty");
            assert(!data_.empty());
            range_ = boost::make_iterator_range(data_.begin(), data_.end() - 1);
        }

        auto get_buffer()
        {
            return boost::asio::buffer(range_.begin(), range_.size());
        }

        std::size_t get_buffer_size()
        {
            return range_.size();
        }

    private:

        packet_array data_;
        boost::iterator_range<packet_array::iterator> range_;
    };

    class test_client
    {
    public:

        test_client(
                const char* const address,
                const std::uint16_t port,
                const std::uint32_t rounds,
                boost::asio::io_service& service) :
            socket_(service),
            completion_timer_(service),
            send_queue_(),
            receive_buffer_(),
            failure_(),
            rounds_(rounds),
            received_count_(0)
        {
            reset_timeout();
            socket_.async_connect(
                boost::asio::ip::udp::endpoint(
                    boost::asio::ip::address::from_string(address), port),
                (
                    [this](const boost::system::error_code& error)
                    {
                        if (error)
                        {
                            this->fail_test("Could not connect to server");
                        }
                        else
                        {
                            this->test_server();
                        }
                    }));
        }

        boost::optional<std::string> failure() const
        {
            if (failure_)
            {
                return failure_;
            }

            if (!send_queue_.empty())
            {
                return std::string("Could not send all packets");
            }

            if (received_count_ != rounds_)
            {
                return received_count_ < rounds_ ?
                    std::string("Received two few packets") :
                    std::string("Received too many packets");
            }

            return boost::none;
        }

    private:

        // Return true if there is from a canceled operation
        static bool canceled_operation(
            const boost::system::error_code& error)
        {
            return error == boost::system::errc::operation_canceled;
        }

        // Return true if there is an error.
        // Canceled opertion is NOT an error
        static bool have_server_error(
            const boost::system::error_code& error)
        {
            return error && !canceled_operation(error);
        }

        static bool valid_server_packet(const sntp_packet& packet)
        {
            const std::uint32_t originate_seconds =
                test::sntp::extract_ulong(
                    packet.get_array(),
                    test::sntp::originate_seconds_offset);
            const std::uint32_t originate_fractional =
                test::sntp::extract_ulong(
                    packet.get_array(),
                    test::sntp::originate_fractional_offset);

            const std::uint8_t mode = packet.get_array()[0] & mode_mask;

            return
                mode == server_indicator &&
                originate_seconds == 0xDEADBEEF &&
                originate_fractional == 0xBEEFDEAD &&
                test::sntp::receive_before_transmit(packet.get_array());
        }

        void reset_timeout()
        {
            completion_timer_.expires_from_now(boost::posix_time::seconds(5));
            completion_timer_.async_wait(
                [this](const boost::system::error_code& error)
                {
                    if (!canceled_operation(error))
                    {
                        this->stop_test();
                    }
                });
        }

        // Cancels all async operations
        void stop_test()
        {
            completion_timer_.cancel();
            socket_.cancel();
        }

        // Marks the test for failure, and cancels all async operations
        void fail_test(std::string fail_message)
        {
            stop_test();
            failure_ = std::move(fail_message);
        }

        // Initiate the server test (sending and receive SNTP packets)
        void test_server()
        {
            // initiate the receive message queue
            receive_message();

            // start sending requests in a specific order
            {
                std::vector<sntp_packet> send_packets;
                send_packets.resize(3);

                // packet 1: invalid version number (dropped)
                // packet 2: packet too short (dropped)
                // packet 3: valid packet
                send_packets[0].get_array()[0] =
                    alarm_condition | invalid_version | client_indicator;

                send_packets[1].get_array()[0] =
                    alarm_condition | valid_version | client_indicator;
                send_packets[1].shrink_buffer();

                send_packets[2].get_array()[0] =
                    alarm_condition | valid_version | client_indicator;
                send_packets[2].get_array()[40] = 0xDE;
                send_packets[2].get_array()[41] = 0xAD;
                send_packets[2].get_array()[42] = 0xBE;
                send_packets[2].get_array()[43] = 0xEF;
                send_packets[2].get_array()[44] = 0xBE;
                send_packets[2].get_array()[45] = 0xEF;
                send_packets[2].get_array()[46] = 0xDE;
                send_packets[2].get_array()[47] = 0xAD;

                for (std::size_t iteration = 0; iteration < rounds_; ++iteration)
                {
                    queue_packet(send_packets[0]);
                    queue_packet(send_packets[1]);
                    queue_packet(send_packets[2]);
                }
            }
        }

        void receive_message()
        {
            socket_.async_receive(
                receive_buffer_.get_buffer(),
                (
                    [this]
                    (const boost::system::error_code& error, const std::size_t bytes)
                    {
                        if (have_server_error(error))
                        {
                            this->fail_test("Problem receiving message");
                        }
                        else if(!canceled_operation(error) &&
                                bytes != sntp_packet::packet_size)
                        {
                            this->fail_test("Invalid packet size received");
                        }
                        else if (!canceled_operation(error))
                        {
                            if (!valid_server_packet(this->receive_buffer_))
                            {
                                this->fail_test("Invalid packet sent by server");
                            }
                            else
                            {
                                ++(this->received_count_);

                                // verify that replayed messages are dropped
                                this->queue_packet(this->receive_buffer_);
                                this->receive_message();
                            }
                        }
                    }));
        }

        void queue_packet(const sntp_packet& packet)
        {
            const bool none_in_flight = send_queue_.empty();
            send_queue_.push(packet);

            if (none_in_flight)
            {
                send_next_packet();
            }
        }

        void send_next_packet()
        {
            if (!send_queue_.empty())
            {
                reset_timeout();
                socket_.async_send(
                    send_queue_.front().get_buffer(),
                    (
                        [this]
                        (const boost::system::error_code& error,
                         const std::size_t bytes)
                        {
                            assert(!this->send_queue_.empty());

                            if (have_server_error(error))
                            {
                                this->fail_test("Problem sending data");
                            }
                            else if (bytes != send_queue_.front().get_buffer_size())
                            {
                                this->fail_test(
                                    "Did not send requested number bytes");
                            }
                            else if(!canceled_operation(error))
                            {
                                this->send_queue_.pop();
                                this->send_next_packet();
                            }
                        }));
            }
        }

    private:

        boost::asio::ip::udp::socket socket_;
        boost::asio::deadline_timer completion_timer_;
        std::queue<sntp_packet> send_queue_;
        sntp_packet receive_buffer_;
        boost::optional<std::string> failure_;
        const std::uint32_t rounds_;
        std::uint32_t received_count_;
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
                argv[0] << " [ip address] [port] [# of rounds]" << std::endl;
        }
        return EXIT_FAILURE;
    }
}

int main(int argc, const char** argv)
{
    if (argc != 4)
    {
        return display_option_error("Four arguments required", argc, argv);
    }

    std::uint16_t port = 0;
    std::uint32_t rounds = 0;

    if (!boost::spirit::qi::parse(
            argv[2],
            argv[2] + strlen(argv[2]),
            (boost::spirit::qi::ushort_ >> boost::spirit::qi::eoi),
            port))
    {
            return display_option_error("Invalid port provided", argc, argv);
    }

    if (!boost::spirit::qi::parse(
            argv[3],
            argv[3] + strlen(argv[3]),
            (boost::spirit::qi::ulong_ >> boost::spirit::qi::eoi),
            rounds))
    {
        return display_option_error("Invalid rounds value", argc, argv);
    }

    try
    {
        boost::asio::io_service service;
        test_client test_client(argv[1], port, rounds, service);
        service.run();

        const boost::optional<std::string> failure = test_client.failure();

        if (!failure)
        {
            std::cout << "Test Passed" << std::endl;
            return EXIT_SUCCESS;
        }
        std::cerr << "Test Failed: " << *failure << std::endl;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Client error: " << error.what() << std::endl;
    }

    return EXIT_FAILURE;
}
