#include <iostream>


#include "Handler.h"
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

void asdds ( client * c, websocketpp::connection_hdl hdl ) {
    std::string msg = "Hello";
  //  c->send ( hdl, msg, websocketpp::frame::opcode::text );
    c->get_alog ( ).write ( websocketpp::log::alevel::app, "Sent Message: " + msg );
}

void socket_handler::connect ( ) {
    websocketpp::lib::error_code ec;

 /*   m_endpoint.set_open_handler ( bind ( &asdds, &m_endpoint, ::_1 ) );

    m_endpoint.set_open_handler ( websocketpp::lib::bind (
        &socket_handler::on_open,
        this,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    m_endpoint.set_fail_handler ( websocketpp::lib::bind (
        &socket_handler::on_fail,
        this,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    m_endpoint.set_close_handler ( websocketpp::lib::bind (
        &socket_handler::on_close,
        this,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    m_endpoint.set_message_handler ( websocketpp::lib::bind (
        &socket_handler::message_handle,
        this,
        websocketpp::lib::placeholders::_1,
        websocketpp::lib::placeholders::_2
    ) );*/

   /* try {
        
        std::cout << "> Trying initiate connection: " << std::endl;
        client::connection_ptr con = m_endpoint.get_connection ( "ws://localhost:9002", ec );

        con->set_open_handler ( websocketpp::lib::bind (
            &socket_handler::on_open,
            this,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ) );
        std::cout << "> Result: " << ec.message ( ) << std::endl;



    }
    catch ( int ex ) {

    }*/
}

socket_handler::socket_handler ( ) {
    try {
        std::string uri = "ws://localhost:9002";


        m_client.set_access_channels ( websocketpp::log::alevel::all );
        m_client.clear_access_channels ( websocketpp::log::alevel::frame_payload );

        m_client.init_asio ( );
        m_client.start_perpetual ( );
        
        m_client.set_open_handler ( websocketpp::lib::bind (
            &socket_handler::on_open,
            this
        ) );

        m_client.set_fail_handler ( websocketpp::lib::bind (
            &socket_handler::on_fail,
            this
        ) );

        m_client.set_close_handler ( websocketpp::lib::bind (
            &socket_handler::on_close,
            this
        ) );

        m_thread.reset ( new websocketpp::lib::thread ( &client::run, &m_client ) );
        
        websocketpp::lib::error_code ec;
        client::connection_ptr con = m_client.get_connection ( uri, ec );
        if ( ec ) {
            std::cout << "could not create connection because: " << ec.message ( ) << std::endl;
            return;
        }

        m_hdl = con->get_handle ( );

        m_client.connect ( con );
        std::cout << "Socket client thread initialized!\n";
        
    }
    catch ( websocketpp::exception const & e ) {
        std::cout << e.what ( ) << std::endl;
    }
    catch ( const std::exception & e ) {
        std::cout << e.what ( ) << std::endl;
    }
    catch ( ... ) {
        std::cout << "other exception" << std::endl;
    }
}

socket_handler::~socket_handler ( ) {

    try {


        m_client.stop_perpetual ( );

        std::cout << "> Closing connection " << std::endl;

        websocketpp::lib::error_code ec;

        m_client.pause_reading ( m_hdl );
        m_client.close ( m_hdl, websocketpp::close::status::going_away, "", ec );
        
        if ( ec ) {
            std::cout << "> Error closing connection : "
                << ec.message ( ) << std::endl;
        }

        m_thread->join ( );

        std::cout << "Socket client handler unitialized!\n";

    }
    catch ( websocketpp::exception const & e ) {
        std::cout << e.what ( ) << std::endl;
    }
    catch ( const std::exception & e ) {
        std::cout << e.what ( ) << std::endl;
    }
    catch ( ... ) {
        std::cout << "other exception" << std::endl;
    }
}

socket_handler * handler;