#ifndef __ASIO_TELNET_CLIENT_H__
#define __ASIO_TELNET_CLIENT_H__

#include <deque>
#include <string>
#include <functional>

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

#ifdef POSIX
#   include <termios.h>
#endif

using boost::asio::ip::tcp;

class AsioTelnetClient
{
public:
	enum { max_read_length = 512 };

	AsioTelnetClient(boost::asio::io_service& io_service, tcp::resolver::iterator endpoint_iterator);

	~AsioTelnetClient();

	void write(const char msg); // pass the write data to the do_write function via the io service in the other thread
	void write(const std::string msg); // pass the write data to the do_write function via the io service in the other thread
	void close();               // call the do_close function via the io service in the other thread

	void setReceivedSocketCallback(std::function<void(const std::string& data)> fn) { callback_receive_data_fn_ = fn; }
	void setClosedSocketCallback(std::function<void()> fn) { callback_closesocket_fn_ = fn; }

	const std::string&  getCurrentLineBuffer() { return current_line_buffer; }
	const std::string&  getPreviousReceivedLineBuffer() { return previous_received_line_buffer; }

	bool  activeSocket() { return socket_.is_open(); }

	void do_close();
	void startTelnet();
private:
	void connect_start(tcp::resolver::iterator endpoint_iterator);

	void connect_complete(const boost::system::error_code& error, tcp::resolver::iterator endpoint_iterator);
	void read_start(void);

	void read_complete(const boost::system::error_code& error, size_t bytes_transferred);

	void do_write(const std::string msg);

	void write_start(void);
	void write_complete(const boost::system::error_code& error);


private:
	int     handleCommand(unsigned char* commandData);
	void    respondToRequest(unsigned char command, unsigned char option);
	void    respondToStatement(unsigned char command, unsigned char option);

private:
	tcp::resolver::iterator endpoint_iterator_;
	boost::asio::io_service& io_service_;   
	std::shared_ptr<boost::thread> thread_;

	tcp::socket socket_;                   
	unsigned char read_msg_[max_read_length + 5];        
	std::deque<char> write_msgs_;                 

	std::string pending_buf_;

	std::string current_line_buffer;
	std::string previous_received_line_buffer;

	std::function<void(const std::string& strData)> callback_receive_data_fn_;
	std::function<void()> callback_closesocket_fn_; 
};

#endif // !__ASIO_TELNET_CLIENT_H__