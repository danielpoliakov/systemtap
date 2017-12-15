// systemtap compile-server web api header
// Copyright (C) 2017 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef __API_H__
#define __API_H__

#include "server.h"
#include <string>
#include <vector>
extern "C" {
#include <json-c/json_object.h>
}

struct file_info
{
    std::string name;
    std::string pkg;
    std::string build_id;
};

class client_request_data
{
public:
    struct json_object *get_json_object() const;

    std::string kver;
    std::string arch;
    std::string base_dir;
    std::string distro_name;
    std::string distro_version;
    std::vector<std::string> cmd_args;
    std::vector<std::string> files;
    std::vector<std::shared_ptr<struct file_info> > file_info;
    std::vector<std::string> env_vars;
    unsigned verbose;
};

std::string get_uuid();

//extern bool
//api_handler(const char *url, const map<string, string> &url_args,
//	    const char *method, ostringstream &output);

void api_add_request_handlers(server &httpd);
void api_cleanup();

#endif	/* __API_H__ */
