// systemtap compile-server utils
// Copyright (C) 2017 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include <string>
#include <sstream>
#include <iomanip>
#include "utils.h"

extern "C" {
#include <uuid/uuid.h>
}

using namespace std;

string get_uuid()
{
    uuid_t uuid;
    ostringstream os;

    uuid_generate(uuid);
    os << hex << setfill('0');
    for (const unsigned char *ptr = uuid; ptr < uuid + sizeof(uuid_t); ptr++)
        os << setw(2) << (unsigned int)*ptr;
    return os.str();
}

