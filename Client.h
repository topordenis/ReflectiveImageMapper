#pragma once


class client {
public:
	client( ){ }
	client ( connection_hdl _con ) {
		con = _con;
	}
	connection_hdl con;
	std::string username;
	std::string hwid;
	connection_hdl* mapper_connection;
};