#pragma once
#include <vector>
namespace Utils {
	void CreateConsole ( );
	void ReleaseConsole ( );
	std::vector<unsigned char> OTPKey ( int ping );
}