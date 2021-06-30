#pragma once
#include <websocketpp/config/debug_asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <websocketpp/extensions/permessage_deflate/enabled.hpp>

using websocketpp::connection_hdl;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;



#include "BinaryPacket.h"


#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

typedef websocketpp::client<websocketpp::config::asio_client> client;
//typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;



enum CLIENT_STATUS {
   CLOSED,
   CONNECTED
};

class socket_handler {
//Handlers
public:
    void on_open ( client * c, connection_hdl hdl );
    void on_close ( client * c, connection_hdl hdl );
    void on_fail ( client * c, connection_hdl hdl );

public:

    void connect ( );
    socket_handler ( );
	~socket_handler ( );
 
    void message_handle ( websocketpp::connection_hdl, client::message_ptr msg );

private:
    websocketpp::connection_hdl m_hdl;
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;
public:
    client m_endpoint;
private:
    CLIENT_STATUS status;
    std::string uri = "localhost";

};


extern std::unique_ptr< socket_handler > handler;


