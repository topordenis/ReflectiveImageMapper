#pragma once

class connection_metadata {
public:
    typedef websocketpp::lib::shared_ptr<connection_metadata> ptr;

    connection_metadata ( int id, websocketpp::connection_hdl hdl, std::string uri )
        : m_id ( id )
        , m_hdl ( hdl )
        , m_status ( "Connecting" )
        , m_uri ( uri )
        , m_server ( "N/A" ) {
    }

    void on_open ( client * c, websocketpp::connection_hdl hdl );

    void on_fail ( client * c, websocketpp::connection_hdl hdl );

    void on_close ( client * c, websocketpp::connection_hdl hdl );

    void on_message ( websocketpp::connection_hdl, client::message_ptr msg );
    websocketpp::connection_hdl get_hdl ( ) const {
        return m_hdl;
    }

    int get_id ( ) const {
        return m_id;
    }

    std::string get_status ( ) const {
        return m_status;
    }

    friend std::ostream & operator<< ( std::ostream & out, connection_metadata const & data );
private:
    int m_id;
    websocketpp::connection_hdl m_hdl;
    std::string m_status;
    std::string m_uri;
    std::string m_server;
    std::string m_error_reason;
};

