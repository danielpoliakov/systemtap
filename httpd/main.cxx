// systemtap compile-server web api server
// Copyright (C) 2017-2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "server.h"
#include "api.h"
#include <iostream>
#include "../util.h"
#include "nss_funcs.h"
#include "utils.h"
#include "../nsscommon.h"

extern "C" {
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <getopt.h>
}

server *httpd = NULL;

static void *
signal_thread(void *arg)
{
    int signal_fd = (int)(long)arg;

    while (1) {
	struct signalfd_siginfo si;
	ssize_t s;

	s = read(signal_fd, &si, sizeof(si));
	if (s != sizeof(si)) {
	    server_error(_F("signal fd read error: %s", strerror(errno)));
	    continue;
	}

	// FIXME: we might think about using SIGHUP to aks us to
	// re-read configuration data.
	if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM
	    || si.ssi_signo == SIGHUP || si.ssi_signo == SIGQUIT) {

	    // Since we're using signalfd(), we can call code that
	    // isn't signal-safe (like server::stop).
	    if (httpd)
		httpd->stop();
	    break;
	}
	else if (si.ssi_signo == SIGCHLD) {
	    // We just ignore SIGCHLD. We need to keep it enabled for
	    // waitpid() to work properly.
	}
	else {
	    server_error(_F("Got unhandled signal %d", si.ssi_signo));
	}
    }
    close(signal_fd);
    return NULL;
}

static void
setup_main_signals(pthread_t *tid)
{
    static sigset_t s;

    /* Block several signals; other threads created by main() will
     * inherit a copy of the signal mask. */
    sigemptyset(&s);
    sigaddset(&s, SIGINT);
    sigaddset(&s, SIGTERM);
    sigaddset(&s, SIGHUP);
    sigaddset(&s, SIGQUIT);
    sigaddset(&s, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &s, NULL);

    /* Create a signalfd. This way we can synchronously handle the
     * signals. */
    int signal_fd = signalfd(-1, &s, SFD_CLOEXEC);
    if (signal_fd < 0) {
	server_error(_F("Failed to create signal file descriptor: %s",
			strerror(errno)));
	exit(1);
    }

    /* Let the special signal thread handle signals. */
    if (pthread_create(tid, NULL, signal_thread, (void *)(long)signal_fd) < 0) {
	server_error(_F("Failed to create thread: %s", strerror(errno)));
	exit(1);
    }
}

// FIXME: the default port of 1234 was just chosen at random. A better
// port default needs to be chosen.
static uint16_t port = 1234;
static string cert_db_path;

void
parse_cmdline(int argc, char *const argv[])
{
    enum {
	LONG_OPT_PORT = 256,
	LONG_OPT_SSL,
	LONG_OPT_LOG,
    };
    static struct option long_options[] = {
        { "port", 1, NULL, LONG_OPT_PORT },
        { "ssl", 1, NULL, LONG_OPT_SSL },
        { "log", 1, NULL, LONG_OPT_LOG },
        { NULL, 0, NULL, 0 }
    };
    while (true) {
	int grc = getopt_long(argc, argv, "", long_options, NULL);
	char *num_endptr;
	unsigned long port_tmp;
	if (grc < 0)
	    break;
	switch (grc) {
	  case LONG_OPT_PORT:
	    errno = 0;
	    port_tmp = strtoul(optarg, &num_endptr, 10);
	    if (*num_endptr != '\0') {
		server_error(_F("%s: cannot parse number '--port=%s'", argv[0],
				optarg));
		exit(1);
	    }
	    if (errno != 0 || port_tmp > 65535) {
		server_error(_F("%s: invalid entry: port must be between"
				" 0 and 65535 '--port=%s'", argv[0], optarg));
		exit(1);
	    }
	    port = (uint16_t)port_tmp;
	    break;
	  case LONG_OPT_SSL:
	    cert_db_path = optarg;
	    break;
	  case LONG_OPT_LOG:
	    start_log(optarg, true);
	    break;
	  default:
	    break;
	}
    }
    for (int i = optind; i < argc; i++) {
	server_error(_F("%s: unrecognized argument '%s'", argv[0], argv[i]));
    }
}

int
main(int argc, char *const argv[])
{
    pthread_t tid;
    
    // Get rid of a few standard environment variables (which might
    // cause us to do unintended things).
    if (unsetenv("IFS") || unsetenv("CDPATH") || unsetenv("ENV")
	|| unsetenv("BASH_ENV")) {
	server_error(_F("unsetenv failed: %s", strerror(errno)));
	return 1;
    }

    // Make sure we're not root. Since we connect directly to the
    // internet, we can't (safely) run as root.
    if (geteuid () == 0) {
	server_error("For security reasons, invocation of stap-httpd as"
		     " root is not supported.");
	return 1;
    }

    setup_main_signals(&tid);

    parse_cmdline(argc, argv);

    // Initialize NSS.
    if (nss_init(cert_db_path) != 0)
      return 1;

    // Create the server and ask the api to register its handlers.
    httpd = new server(port, cert_db_path);
    api_add_request_handlers(*httpd);

    // Wait for the server to shut itself down.
    httpd->wait();
    delete httpd;

    // Clean up the signal thread.
    pthread_join(tid, NULL);

    // Ask the api to do its cleanup.
    api_cleanup();

    // Shutdown NSS.
    nss_shutdown(cert_db_path);

    end_log();
    return 0;
}
