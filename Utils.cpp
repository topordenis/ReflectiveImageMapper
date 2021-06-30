#include  <vector>
#include "Utils.h"
#include <chrono>
#include <complex>
#include <consoleapi.h>
#include <consoleapi2.h>

namespace Utils
{
    void CreateConsole ( ) {

        AllocConsole ( );

        freopen_s ( ( _iobuf ** ) __acrt_iob_func ( 0 ), "conin$", "r", ( _iobuf * ) __acrt_iob_func ( 0 ) );
        freopen_s ( ( _iobuf ** ) __acrt_iob_func ( 1 ), "conout$", "w", ( _iobuf * ) __acrt_iob_func ( 1 ) );
        freopen_s ( ( _iobuf ** ) __acrt_iob_func ( 2 ), "conout$", "w", ( _iobuf * ) __acrt_iob_func ( 2 ) );

        SetConsoleTitleA ( "Mapper Image Console" );
    }
    void ReleaseConsole ( ) {
        fclose ( ( _iobuf * ) __acrt_iob_func ( 0 ) );
        fclose ( ( _iobuf * ) __acrt_iob_func ( 1 ) );
        fclose ( ( _iobuf * ) __acrt_iob_func ( 2 ) );

        FreeConsole ( );
    }

    std::vector<unsigned char> OTPKey ( int ping ) {
        std::vector<unsigned char> key;


        int delay = ( ping * 2 ) * 8;
        const auto p1 = std::chrono::system_clock::now ( );

        auto minute = std::chrono::duration_cast< std::chrono::minutes >(
            p1.time_since_epoch ( ) ).count ( );

        auto miliseconds = std::chrono::duration_cast< std::chrono::milliseconds >(
            p1.time_since_epoch ( ) ).count ( );


        int end = ( miliseconds / delay ) % 10;
        int end_minute = ( minute % 10 );
        if ( end_minute == 0 )
            end_minute = 1;
        int pow = std::pow ( end, end_minute );
        if ( pow == 0 ) {
            pow = 53;
        }

        pow *= std::chrono::duration_cast< std::chrono::minutes >( p1.time_since_epoch ( ) ).count ( ) / delay;

        pow = std::abs ( pow );


        for ( int i = 0; i < 16; i++ )

            key.push_back ( ( char ) ( pow % ( i * i + ( i + 1 ) ) ) );

        return key;

    }


}