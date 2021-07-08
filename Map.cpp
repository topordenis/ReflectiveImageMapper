
#include <iostream>
#include <string>
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include "Map.h"

namespace Map {
	void write ( std::string buffer ) {

		PIMAGE_NT_HEADERS pOldNtHeader = reinterpret_cast< IMAGE_NT_HEADERS * >( buffer.data() + reinterpret_cast< IMAGE_DOS_HEADER * >( buffer.data() )->e_lfanew );
		PIMAGE_OPTIONAL_HEADER pOldOptHeader = &pOldNtHeader->OptionalHeader;
		PIMAGE_FILE_HEADER pOldFileHeader = &pOldNtHeader->FileHeader;


	}
}