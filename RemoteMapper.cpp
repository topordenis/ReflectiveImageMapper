
#include <iostream>
#include <string>
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include "RemoteMapper.h"



namespace RemoteMapper {
	void * pBase;
	std::uintptr_t pEntry;

	void AllocateSize ( std::uint64_t size ) {
		
		pBase = std::malloc ( size );


	}


}