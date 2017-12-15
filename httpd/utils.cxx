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
#include "../util.h"

extern "C" {
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <spawn.h>
}

using namespace std;

string
get_uuid()
{
    uuid_t uuid;
    ostringstream os;

    uuid_generate(uuid);
    os << hex << setfill('0');
    for (const unsigned char *ptr = uuid; ptr < uuid + sizeof(uuid_t); ptr++)
        os << setw(2) << (unsigned int)*ptr;
    return os.str();
}

// Runs a command and waits for it to finish. Command output is
// written to stdout_path and stderr_path. Returns < 0 on
// error. Returns the command return code otherwise.
int
execute_and_capture(int verbose, const vector<string> &args,
		    const vector<string> &env_vars,
		    string stdout_path, string stderr_path)
{
    // Handle capturing stdout and stderr (along with using /dev/null
    // for stdin).
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc == 0) {
	rc = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null",
					      O_RDONLY, S_IRWXU);
    }
    if (rc == 0) {
	rc = posix_spawn_file_actions_addopen(&actions, 1,
					      stdout_path.c_str(),
					      O_WRONLY|O_CREAT,
					      S_IRWXU);
    }
    if (rc == 0) {
	rc = posix_spawn_file_actions_addopen(&actions, 2,
					      stderr_path.c_str(),
					      O_WRONLY|O_CREAT,
					      S_IRWXU);
    }
    if (rc != 0) {
	clog << "posix_spawn_file_actions failed: " << strerror(errno)
	     << endl;
	return rc > 0 ? -rc : rc;
    }

    // Run the command.
    pid_t pid;
    if (env_vars.size() > 0)
      pid = stap_spawn(verbose, args, &actions, env_vars);
    else
      pid = stap_spawn(verbose, args, &actions);
    clog << "spawn returned " << pid << endl;

    // If stap_spawn() failed, no need to wait.
    if (pid == -1) {
	rc = errno;
	clog << "Error in spawn: " << strerror(errno) << endl;
	(void)posix_spawn_file_actions_destroy(&actions);
	return rc > 0 ? -rc : rc;
    }

    // Wait on the spawned process to finish.
    rc = stap_waitpid(0, pid);
    if (rc < 0) {			// stap_waitpid() failed
	clog << "waitpid failed: " << strerror(errno) << endl;
    }
    (void)posix_spawn_file_actions_destroy(&actions);
    return rc;
}
