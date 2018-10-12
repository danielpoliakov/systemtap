// systemtap compile-server server backends.
// Copyright (C) 2017-2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef __BACKEND_H__
#define __BACKEND_H__

#include <string>
#include <vector>
#include "api.h"

class backend_base
{
public:
    virtual ~backend_base() { }

    virtual bool can_generate_module(const client_request_data *crd) = 0;
    virtual int generate_module(const client_request_data *crd,
				const std::vector<std::string> &argv,
				const std::string &uuid,
				const std::string &stdout_path,
				const std::string &stderr_path) = 0;
};

void get_backends(std::vector<backend_base *> &backends);

#endif /* __BACKEND_H__ */
