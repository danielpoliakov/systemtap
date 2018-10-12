// systemtap compile-server utils header
// Copyright (C) 2017-2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>
#include <vector>

void
server_error(const std::string &msg);

std::string get_uuid();

int
execute_and_capture(int verbose,
		    const std::vector<std::string> &args,
		    const std::vector<std::string> &env_vars,
		    std::string stdout_path, std::string stderr_path);

int
get_file_hash(const std::string &pathname, std::string &result);

bool
make_temp_dir(std::string &path);

#endif /* __UTILS_H__ */
