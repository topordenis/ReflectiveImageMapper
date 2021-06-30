#include <iostream>


#include "Handler.h"

void on_message ( client * c, websocketpp::connection_hdl hdl, message_ptr msg ) {
    std::cout << "on_message called with hdl: " << hdl.lock ( ).get ( )
        << " and message: " << msg->get_payload ( )
        << std::endl;


    websocketpp::lib::error_code ec;

    c->send ( hdl, msg->get_payload ( ), msg->get_opcode ( ), ec );
    if ( ec ) {
        std::cout << "Echo failed because: " << ec.message ( ) << std::endl;
    }
}
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
            this
        ) );
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