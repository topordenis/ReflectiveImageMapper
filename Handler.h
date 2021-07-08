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
    void on_open (  );
    void on_close (  );
    void on_fail ( );
   
public:

    void connect ( );
    socket_handler ( );
	~socket_handler ( );
 
    void message_handle ( websocketpp::connection_hdl, client::message_ptr msg );

private:
    
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;
public:
    client m_client;
    websocketpp::connection_hdl m_hdl;
    std::string m_key;
private:
    CLIENT_STATUS status;

};


extern socket_handler* handler;
extern void* baseToSend;


