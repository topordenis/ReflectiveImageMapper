#include <iostream>


#include "Handler.h"


void socket_handler::connect ( ) {
    websocketpp::lib::error_code ec;

    try {
        client::connection_ptr con = m_endpoint.get_connection ( uri, ec );

        if ( ec ) {
            std::cout << "> Connect initialization error: " << ec.message ( ) << std::endl;
            return;
        }


        con->set_open_handler ( websocketpp::lib::bind (
            &socket_handler::on_open,
            this,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ) );
        con->set_fail_handler ( websocketpp::lib::bind (
            &socket_handler::on_fail,
            this,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ) );
        con->set_close_handler ( websocketpp::lib::bind (
            &socket_handler::on_close,
            this,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ) );
        con->set_message_handler ( websocketpp::lib::bind (
            &socket_handler::message_handle,
            this,
            websocketpp::lib::placeholders::_1,
            websocketpp::lib::placeholders::_2
        ) );
    }
    catch ( int ex ) {

    }
}

socket_handler::socket_handler ( ) {
    try {
        
        m_endpoint.clear_access_channels ( websocketpp::log::alevel::all );
        m_endpoint.clear_error_channels ( websocketpp::log::elevel::all );

        m_endpoint.init_asio ( );
        m_endpoint.start_perpetual ( );

        m_thread.reset ( new websocketpp::lib::thread ( &client::run, &m_endpoint ) );

        std::cout << "Socket client handler initialized!\n";
  
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

        m_endpoint.stop_perpetual ( );

        websocketpp::lib::error_code ec;

        m_endpoint.close ( m_hdl, websocketpp::close::status::going_away, "", ec );

        if ( ec ) 
            std::cout << "> Error closing connection : "
                << ec.message ( ) << std::endl;
        


        m_thread->join ( );
        std::cout << "Socket client handler initialized!\n";

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

std::unique_ptr< socket_handler > handler;