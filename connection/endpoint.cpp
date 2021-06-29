#pragma warning
#include "inc.h"

std::ostream & operator<< ( std::ostream & out, connection_metadata const & data ) {
    out << "> URI: " << data.m_uri << "\n"
        << "> Status: " << data.m_status << "\n"
        << "> Remote Server: " << ( data.m_server.empty ( ) ? "None Specified" : data.m_server ) << "\n"
        << "> Error/close reason: " << ( data.m_error_reason.empty ( ) ? "N/A" : data.m_error_reason );

    return out;
}


/*context_ptr on_tls_init ( const char * hostname, websocketpp::connection_hdl ) {
    context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context> ( boost::asio::ssl::context::sslv23 );

    try {
        ctx->set_options ( boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::single_dh_use );


        ctx->set_verify_mode ( boost::asio::ssl::verify_peer );
        ctx->set_verify_callback ( bind ( &ssl_manager::verify_certificate, hostname, ::_1, ::_2 ) );

        // Here we load the CA certificates of all CA's that this client trusts.
        ctx->load_verify_file ( "ca-chain.cert.pem" );
    }
    catch ( std::exception & e ) {
        std::cout << e.what ( ) << std::endl;
    }
    return ctx;
}*/
websocketpp::connection_hdl websocket_endpoint::connect ( std::string const & uri ) {
    websocketpp::lib::error_code ec;

   // m_endpoint.set_tls_init_handler ( bind ( &on_tls_init, uri.c_str ( ), ::_1 ) );
    
    client::connection_ptr con = m_endpoint.get_connection ( uri, ec );

    if ( ec ) {
        std::cout << "> Connect initialization error: " << ec.message ( ) << std::endl;
        return con->get_handle ( );
    }

    int new_id = m_next_id++;
    connection_metadata::ptr metadata_ptr ( new connection_metadata ( new_id, con->get_handle ( ), uri ) );


    m_connection_list [ new_id ] = metadata_ptr;
   
    con->set_open_handler ( websocketpp::lib::bind (
        &connection_metadata::on_open,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    con->set_fail_handler ( websocketpp::lib::bind (
        &connection_metadata::on_fail,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    con->set_close_handler ( websocketpp::lib::bind (
        &connection_metadata::on_close,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1
    ) );
    con->set_message_handler ( websocketpp::lib::bind (
        &connection_metadata::on_message,
        metadata_ptr,
        websocketpp::lib::placeholders::_1,
        websocketpp::lib::placeholders::_2
    ) );

   

    m_endpoint.connect ( con );
    
    return con->get_handle ( );
}

void websocket_endpoint::close ( int id, websocketpp::close::status::value code, std::string reason ) {
    websocketpp::lib::error_code ec;

    con_list::iterator metadata_it = m_connection_list.find ( id );
    if ( metadata_it == m_connection_list.end ( ) ) {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }

    m_endpoint.close ( metadata_it->second->get_hdl ( ), code, reason, ec );
    if ( ec ) {
        std::cout << "> Error initiating close: " << ec.message ( ) << std::endl;
    }
}

void websocket_endpoint::send ( int id, std::string message ) {
    websocketpp::lib::error_code ec;

    con_list::iterator metadata_it = m_connection_list.find ( id );
    if ( metadata_it == m_connection_list.end ( ) ) {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }

    m_endpoint.send ( metadata_it->second->get_hdl ( ), message, websocketpp::frame::opcode::text, ec );
    if ( ec ) {
        std::cout << "> Error sending message: " << ec.message ( ) << std::endl;
        return;
    }

   // metadata_it->second->record_sent_message ( message );
}