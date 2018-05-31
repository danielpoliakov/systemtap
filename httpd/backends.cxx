// systemtap compile-server server backends.
// Copyright (C) 2017 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "backends.h"
#include <iostream>
#include <fstream>
#include "../util.h"
#include "utils.h"

extern "C" {
#include <string.h>
#include <glob.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
}

using namespace std;


class default_backend : public backend_base
{
public:
    
    bool can_generate_module(const client_request_data *) {
	return true;
    }
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);
};

int
default_backend::generate_module(const client_request_data *crd,
				 const vector<string> &,
				 const string &,
				 const string &,
				 const string &stdout_path,
				 const string &stderr_path)
{
    ofstream stdout_stream, stderr_stream;

    // Create an empty stdout file.
    stdout_stream.open(stdout_path);
    if (stdout_stream.is_open()) {
	stdout_stream.close();
    }

    // Create an stderr file with an error message.
    stderr_stream.open(stderr_path);
    if (stderr_stream.is_open()) {
	stderr_stream << "Error: the server cannot create a module for kernel "
		      << crd->kver << ", architecture " << crd->arch
		      << ", distro " << crd->distro_name << endl;
	stderr_stream.close();
    }
    return 1;
}


class local_backend : public backend_base
{
public:
    local_backend();

    bool can_generate_module(const client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // <kernel version, build tree path>
    map<string, string> supported_kernels;

    string distro_name;

    // The current architecture.
    string arch;
};


local_backend::local_backend()
{
    glob_t globber;
    string pattern = "/lib/modules/*/build";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);

    if (rc) {
	// We weren't able to find any kernel build trees. This isn't
	// a fatal error, since one of the other backends might be
	// able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see
	// kernel build trees installed at startup. If a kernel build
	// tree gets installed after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];

	supported_kernels.insert({kernel_release_from_build_tree(path), path});
    }
    globfree(&globber);

    // Notice we don't error if we can't get the distro name. This
    // isn't a fatal error, since other backends might be able to
    // handle this request.
    vector<string> info;
    get_distro_info(info);
    if (! info.empty()) {
	distro_name = info[0];
	transform(distro_name.begin(), distro_name.end(), distro_name.begin(), ::tolower);
    }

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;
}

bool
local_backend::can_generate_module(const client_request_data *crd)
{
    // See if we support the kernel/arch/distro combination.
    if (supported_kernels.count(crd->kver) == 1 && arch == crd->arch
	&& distro_name == crd->distro_name) {
	return true;
    }

    return false;
}

int
local_backend::generate_module(const client_request_data *crd,
			       const vector<string> &argv,
			       const string &,
			       const string &,
			       const string &stdout_path,
			       const string &stderr_path)
{
    // Make sure we're running the correct version of systemtap.
    vector<string> cmd = argv;
    cmd[0] = string(BINDIR) + "/stap";
    return execute_and_capture(2, cmd, crd->env_vars,
			       stdout_path, stderr_path);
}


class container_backend : public backend_base
{
public:
    container_backend();

    bool can_generate_module(const struct client_request_data *crd);
    int generate_module(const client_request_data *crd,
			const vector<string> &argv,
			const string &tmp_dir,
			const string &uuid,
			const string &stdout_path,
			const string &stderr_path);

private:
    // The docker executable path.
    string docker_path;

    // The container data directory.
    string datadir;
    
    // List of container data filenames. <distro name, path>
    map<string, string> data_files;

    // The current architecture.
    string arch;

    // The script path that builds a container.
    string container_build_script_path;
};


container_backend::container_backend()
{
    try {
	docker_path = find_executable("docker");
	// If find_executable() can't find the path, it returns the
	// name you passed it.
	if (docker_path == "docker")
	    docker_path.clear();
    }
    catch (...) {
	// It really isn't an error for the system to not have the
	// "docker" executable. We'll just disallow builds using the
	// container backend (down in
	// container_backend::can_generate_module()).
	docker_path.clear();
    }
    
    container_build_script_path = string(PKGLIBDIR)
	+ "/httpd/docker/stap_build_docker_image.py";

    datadir = string(PKGDATADIR) + "/httpd/docker";

    glob_t globber;
    string pattern = datadir + "/*.json";
    int rc = glob(pattern.c_str(), GLOB_ERR, NULL, &globber);
    if (rc) {
	// We weren't able to find any JSON docker data files. This
	// isn't a fatal error, since one of the other backends might
	// be able to satisfy requests.
	//
	// FIXME: By reading the directory here, we'll only see distro
	// json files installed at startup. If one gets installed
	// after startup, we won't see it.
	return;
    }
    for (unsigned int i = 0; i < globber.gl_pathc; i++) {
	string path = globber.gl_pathv[i];
	
	size_t found = path.find_last_of("/");
	if (found != string::npos) {
	    // First, get the file basename ("FOO.json").
	    string filename = path.substr(found + 1);

	    // Now, chop off the .json extension.
	    size_t found = filename.find_last_of(".");
	    if (found != string::npos) {
		// Notice we're lowercasing the distro name to make
		// things simpler.
		string distro = filename.substr(0, found);
		transform(distro.begin(), distro.end(), distro.begin(),
			  ::tolower);
		data_files.insert({distro, path});
	    }
	}
    }
    globfree(&globber);

    // Get the current arch name.
    struct utsname buf;
    (void)uname(&buf);
    arch = buf.machine;
}

bool
container_backend::can_generate_module(const client_request_data *crd)
{
    // If we don't have a docker executable, we're done.
    if (docker_path.empty())
	return false;

    // We have to see if we have a JSON data file for that distro and
    // the arches match.
    if (data_files.count(crd->distro_name) == 1 && arch == crd->arch) {
	return true;
    }

    return false;
}

int
container_backend::generate_module(const client_request_data *crd,
				const vector<string> &argv,
				const string &tmp_dir,
				const string &uuid,
				const string &stdout_path,
				const string &stderr_path)
{
    vector<string> images_to_remove;
    vector<string> containers_to_remove;

    // Handle capturing the container build and run stdout and stderr
    // (along with using /dev/null for stdin). If the client requested
    // it, just use stap's stdout/stderr files.
    string container_stdout_path, container_stderr_path;
    if (crd->verbose >= 3) {
	container_stdout_path = stdout_path;
	container_stderr_path = stderr_path;
    }
    else {
	container_stdout_path = tmp_dir + "/container_stdout";
	container_stderr_path = tmp_dir + "/container_stderr";
    }

    // Grab a JSON representation of the client_request_data, and
    // write it to a file (so the script that generates the docker
    // file(s) knows what it is supposed to be doing).
    string build_data_path = string(tmp_dir) + "/build_data.json";
    struct json_object *root = crd->get_json_object();
    server_error(_F("JSON data: %s", json_object_to_json_string(root)));
    ofstream build_data_file;
    build_data_file.open(build_data_path, ios::out);
    build_data_file << json_object_to_json_string(root);
    build_data_file.close();
    json_object_put(root);

    // Put the date and time in the image name. This will make it
    // easier to know which container images we've created (and when
    // they were created).
    //
    // Why 13 characters in the date and time buffer? 4 charaters
    // (year) + 2 charaters (month) + 2 charaters (day) + 2 charaters
    // (hour) + 2 charaters (minute) + 1 charater (null character) = 13
    // characters total.
    char datetime[13] = { '\0' };
    time_t t = time(NULL);
    struct tm tm_result;
    if (gmtime_r(&t, &tm_result) != NULL)
	strftime(&datetime[0], sizeof(datetime), "%Y%m%d%H%M", &tm_result);

    string stap_image_uuid = "stap." + uuid + "." + datetime;

    // Kick off building the container image. Note we're using the
    // UUID as the container image name. This keeps us from trying to
    // build multiple images with the same name at the same time.
    vector<string> cmd_args;
#if defined(PYTHON3_BASENAME)
    cmd_args.push_back(PYTHON3_BASENAME);
#elif defined(PYTHON_BASENAME)
    cmd_args.push_back(PYTHON_BASENAME);
#else
#error "Couldn't find python version 2 or 3."
#endif
    cmd_args.push_back(container_build_script_path);
    cmd_args.push_back("--distro-file");
    cmd_args.push_back(data_files[crd->distro_name]);
    cmd_args.push_back("--build-file");
    cmd_args.push_back(build_data_path);
    cmd_args.push_back("--data-dir");
    cmd_args.push_back(datadir);
    cmd_args.push_back(stap_image_uuid);

    int rc = execute_and_capture(2, cmd_args, crd->env_vars,
				 container_stdout_path, container_stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error(_F("%s failed.",
			container_build_script_path.c_str()));
	return -1;
    }

    // The client can optionally send over a "client.zip" file, which
    // was unziped up in build_info::module_build(). If it exists, we
    // need to copy those files down into the container image before
    // we run stap.
    for (auto i = crd->files.begin(); i != crd->files.end(); i++) {
	if (*i == "client.zip") {
	    // First, create a docker file.
	    string docker_file_path = crd->base_dir + "/files.docker";
	    ofstream docker_file;
	    docker_file.open(docker_file_path, ios::out);
	    docker_file << "FROM " << stap_image_uuid << endl;
	    docker_file << "MAINTAINER http://sourceware.org/systemtap/"
			<< endl;
	    docker_file << "COPY . " << tmp_dir << "/" << endl;
	    docker_file.close();
	    // Grab another uuid.
	    stap_image_uuid = get_uuid();

	    // Now run "docker build" with that docker file.
	    cmd_args.clear();
	    cmd_args.push_back("docker");
	    cmd_args.push_back("build");
	    cmd_args.push_back("-t");
	    cmd_args.push_back(stap_image_uuid);
	    cmd_args.push_back("-f");
	    cmd_args.push_back(docker_file_path);
	    cmd_args.push_back(crd->base_dir);

	    rc = execute_and_capture(2, cmd_args, crd->env_vars,
				     container_stdout_path, container_stderr_path);
	    server_error(_F("Spawned process returned %d", rc));
	    if (rc != 0) {
		server_error("docker build failed.");
		return -1;
	    }

	    // We want to remove the image that we just built.
	    images_to_remove.push_back(stap_image_uuid);
	    break;
	}
    }

    // We need a unique name for the container that "docker run stap
    // ..." will create, so grab another uuid.
    string stap_container_uuid = get_uuid();

    // If we're here, we built the container successfully. Now start
    // the container and run stap. First, build up the command line
    // arguments.
    cmd_args.clear();
    cmd_args.push_back("docker");
    cmd_args.push_back("run");
    cmd_args.push_back("--name");
    cmd_args.push_back(stap_container_uuid);
    for (auto i = crd->env_vars.begin(); i < crd->env_vars.end(); ++i) {
        cmd_args.push_back("-e");
        cmd_args.push_back(*i);
    }

    // When running "stap --tmpdir=/tmp/FOO", your current directory
    // needs to be /tmp/FOO for stap to run successfully (for some odd
    // reason).
    cmd_args.push_back("-w");
    cmd_args.push_back(tmp_dir);

    cmd_args.push_back(stap_image_uuid);
    for (auto it = argv.begin(); it != argv.end(); it++) {
	cmd_args.push_back(*it);
    }

    int saved_rc = execute_and_capture(2, cmd_args, crd->env_vars,
				       stdout_path, stderr_path);
    server_error(_F("Spawned process returned %d", rc));
    if (rc != 0) {
	server_error("docker run failed.");
    }

    if (saved_rc == 0) {
	// At this point we've built the container and run stap
	// successfully. Grab the results (if any) from the container.
	cmd_args.clear();
	cmd_args.push_back("docker");
	cmd_args.push_back("cp");
	cmd_args.push_back(stap_container_uuid + ":" + tmp_dir);
	cmd_args.push_back("/tmp");
	rc = execute_and_capture(2, cmd_args, crd->env_vars,
				 container_stdout_path, container_stderr_path);
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("docker cp failed.");
	}
    }
    containers_to_remove.push_back(stap_container_uuid);

    // OK, at this point we've created a container, run stap, and
    // copied out any result. Let's do a little cleanup and delete the
    // last layer. We'll leave (for now) the container with all the
    // files, but delete the layer that got created as stap was run
    // (since there is no reuse there).
    //
    // docker rm/rmi stap_container_uuid
    //
    // Note that we have to remove the containers first, because they
    // depend on the images.

    // FIXME: MORE CLEANUP NEEDED!
    //
    // Note that we're not removing the initial docker image we built,
    // so if the user turns right around again and builds another
    // script that image will get reused. But, that initial docker
    // image never gets deleted currently. The "docker images" command
    // knows when an image was created, but not the last time it was
    // used.
    //
    // We might be able to tie in the information from "docker ps -a",
    // which lists all containers, and when they were created. Since
    // the containers are short-lived (they just exist to run "stap"),
    // their creation date is really the last used date of the related
    // image. But, of course we delete that container at the end of
    // every run so that info gets deleted. In theory we could leave
    // that container around and every so often run a python script
    // that puts the two bits of information together and deletes
    // images and containers that haven't been used in a while.

    if (! containers_to_remove.empty()) {
	cmd_args.clear();
	cmd_args.push_back("docker");
	cmd_args.push_back("rm");
	for (auto i = containers_to_remove.begin();
	     i != containers_to_remove.end(); i++) {
	    cmd_args.push_back(*i);
	}
	rc = execute_and_capture(2, cmd_args, crd->env_vars,
				 container_stdout_path, container_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("docker rm failed.");
	}
    }
    if (! images_to_remove.empty()) {
	cmd_args.clear();
	cmd_args.push_back("docker");
	cmd_args.push_back("rmi");
	for (auto i = images_to_remove.begin(); i != images_to_remove.end();
	     i++) {
	    cmd_args.push_back(*i);
	}
	rc = execute_and_capture(2, cmd_args, crd->env_vars,
				 container_stdout_path, container_stderr_path);
	// Note that we're ignoring any errors here.
	server_error(_F("Spawned process returned %d", rc));
	if (rc != 0) {
	    server_error("docker rmi failed.");
	}
    }
    return saved_rc;
}

static vector<backend_base *>saved_backends;
static void backends_atexit_handler()
{
    if (!saved_backends.empty()) {
	for (auto it = saved_backends.begin(); it != saved_backends.end();
	     it++) {
	    delete *it;
	}
	saved_backends.clear();
    }
}

void
get_backends(vector<backend_base *> &backends)
{
    std::atexit(backends_atexit_handler);
    if (saved_backends.empty()) {
	// Note that order *is* important here. We want to try the
	// local backend first (since it would be the fastest), then
	// the container backend, and finally the default backend
	// (which just returns an error).
	saved_backends.push_back(new local_backend());
	saved_backends.push_back(new container_backend());
	saved_backends.push_back(new default_backend());
    }
    backends.clear();
    backends = saved_backends;
}
