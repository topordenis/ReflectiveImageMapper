#pragma once

class websocket_endpoint {
private:
    typedef std::map<int, connection_metadata::ptr> con_list;

   
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;

    con_list m_connection_list;
    int m_next_id;
public:
    client m_endpoint;
    websocket_endpoint ( ) : m_next_id ( 0 ) {
        m_endpoint.clear_access_channels ( websocketpp::log::alevel::all );
        m_endpoint.clear_error_channels ( websocketpp::log::elevel::all );

        m_endpoint.init_asio ( );
        m_endpoint.start_perpetual ( );

        m_thread.reset ( new websocketpp::lib::thread ( &client::run, &m_endpoint ) );
    }

    ~websocket_endpoint ( ) {
        m_endpoint.stop_perpetual ( );

        for ( con_list::const_iterator it = m_connection_list.begin ( ); it != m_connection_list.end ( ); ++it ) {
            if ( it->second->get_status ( ) != "Open" ) {
                // Only close open connections
                continue;
            }

            std::cout << "> Closing connection " << it->second->get_id ( ) << std::endl;

            websocketpp::lib::error_code ec;
            m_endpoint.close ( it->second->get_hdl ( ), websocketpp::close::status::going_away, "", ec );
            if ( ec ) {
                std::cout << "> Error closing connection " << it->second->get_id ( ) << ": "
                    << ec.message ( ) << std::endl;
            }
        }

        m_thread->join ( );
    }

public:
    websocketpp::connection_hdl connect ( std::string const & uri );
    void close ( int id, websocketpp::close::status::value code, std::string reason );
    void send ( int id, std::string message );
};
