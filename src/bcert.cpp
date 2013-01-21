#include "util.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include "bcert/bcert.pb.h"

/* from util.cpp
#include "sync.h"
#include "version.h"
#include "ui_interface.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {
    namespace program_options {
        std::string to_internal(const std::string&);
    }
}

#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdarg.h>

#ifdef WIN32
#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h> // for _commit 
#include "shlobj.h"
#elif defined(__linux__)
# include <sys/prctl.h>
#endif
*/

using namespace std;

bool ReadCertFile(const string filename)
{
    boost::filesystem::path pathCerts = GetDataDir() / "certs";
    boost::filesystem::path pathCert = pathCerts / filename;

    boost::filesystem::ifstream file(pathCert);
    if (!file.good())
        return true; // No bitcoin.conf file is OK
    return false;
}
