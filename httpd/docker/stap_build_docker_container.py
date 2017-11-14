#! /usr/bin/python

from __future__ import print_function
import json
import os
import sys
import string
import tempfile

def _eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def _usage():
    """Display command-line usage."""
    _eprint("Usage: %s [-v] --distro-ver=DVER --kernel-ver=KVER JSON_FILE" % sys.argv[0])
    sys.exit(1)

def main():
    """Main function."""
    import getopt

    verbose = 0
    ivars = {}

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 4:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v', ['distro-ver=', 'kernel-ver='])
    except getopt.GetoptError as err:
        _eprint("Error: %s" % err)
        _usage()
    for (opt, value) in opts:
        if opt == '-v':
            verbose += 1
        elif opt == '--distro-ver':
            ivars['DVER'] = value
        elif opt == '--kernel-ver':
            ivars['KVER'] = value
            
    if len(pargs) != 1:
        _eprint("No JSON file specified.")
        _usage()
    if not 'DVER' in ivars or not 'KVER' in ivars:
        _eprint("Arguments '--distro-ver' and '--kernel-ver' are required.")
        _usage()

    # Create a temporary directory for our use.
    tmpdir_path = tempfile.mkdtemp()

    jfile = open(pargs[0])
    try:
        jdata = json.load(jfile)
    except json.ValueError as err:
        _eprint("Error: Invalid JSON input: %s" % err)
        jfile.close()
        sys.exit(1)
        
    jfile.close()

    # FIXME: We need to validate the JSON data here, making sure we've
    # got everything we need.
    if not 'docker_stages' in jdata:
        _eprint("Error: Missing 'docker_stages' data in %s." % pargs[0])
        sys.exit(1)
    
    docker_stages = []
    for (id, stage_info) in jdata["docker_stages"].items():
        # Validate stage info.
        if not 'name' in stage_info or not 'data' in stage_info:
            _eprint("Error: docker_stages['%s'] isn't complete." % id)
            break
    
        # Now treat the stage data as a template, and substitute the
        # information we've got. Why aren't we using docker's 'ARG'
        # directive? There are places, like in 'FROM' directives, that
        # you can't use 'ARG' variables. So, we're rolling our own.
        orig_dockerfile_data = string.join(stage_info['data'], '\n')
        orig_dockerfile_data + '\n'
        template = string.Template(orig_dockerfile_data)
        dockerfile_data = template.substitute(ivars)
        
        # Now treat the stage name also as a template, and substitute
        # the information we've got.
        template = string.Template(stage_info['name'])
        dockerfile_name_base = template.substitute(ivars)

        if verbose:
            print("%s dockerfile data:" % (dockerfile_name_base))
            print('==========')
            print(dockerfile_data)
            print('==========')

        # Write the dockerfile data to a file.
        dockerfile_name = "%s.docker" % dockerfile_name_base
        tmpfile = open(tmpdir_path + ("/%s" % dockerfile_name), "w")
        tmpfile.write(dockerfile_data)
        tmpfile.close()

        docker_stages.append(dockerfile_name_base)

    if len(docker_stages) == 0:
        _eprint("Error: No docker stages created.")
        sys.exit(1)
        
    print("created files in %s\n" % tmpdir_path)

    # At this point we've created all the docker files. Actually
    # build the docker container(s). Arguments:
    #
    #   -t TAG:  Repository names (and optionally with tags) to be
    #            applied to the resulting image in case of success.
    #   -f, --file=PATH/Dockerfile:  Path to the Dockerfile to use.
    #
    for dockerfile_name_base in docker_stages:
        cmd = ("docker build -t %s -f %s/%s.docker %s"
               % (dockerfile_name_base, tmpdir_path, dockerfile_name_base,
                  tmpdir_path))
        if verbose:
            print("Running: %s" % cmd)
        rc = os.system(cmd)
        if rc != 0:
            if os.WIFEXITED(rc):
                rc = os.WEXITSTATUS(rc)
            _eprint("Error: \"%s\" failed, status %d" % (cmd, rc))
            sys.exit(1)

if __name__ == '__main__':
    main()
