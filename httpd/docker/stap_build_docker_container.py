#! /usr/bin/python

from __future__ import print_function
import json
import os
import os.path
import sys
import string
import tempfile
import shutil

def _eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def _usage():
    """Display command-line usage."""
    _eprint("Usage: %s [-v] --distro-file DISTRO_JSON_FILE --build-file DATA_JSON_FILE --data-dir DATA_DIR DOCKER_TAG" % sys.argv[0])
    sys.exit(1)

def main():
    """Main function."""
    import getopt

    verbose = 0
    ivars = {}

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 5:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v',
                                      ['distro-file=', 'build-file=',
                                       'data-dir='])
    except getopt.GetoptError as err:
        _eprint("Error: %s" % err)
        _usage()
    for (opt, value) in opts:
        if opt == '-v':
            verbose += 1
        elif opt == '--distro-file':
            ivars['DISTRO_FILE'] = value
        elif opt == '--build-file':
            ivars['BUILD_FILE'] = value
        elif opt == '--data-dir':
            ivars['DATA_DIR'] = value
            
    if len(pargs) != 1:
        _eprint("No DOCKER_TAG specified.")
        _usage()
    if not 'DISTRO_FILE' in ivars or not 'BUILD_FILE' in ivars \
       or not 'DATA_DIR' in ivars:
        _eprint("Arguments '--distro-file', '--build-file', and '--data-dir' are required.")
        _usage()
    ivars['DOCKER_TAG'] = pargs[0]

    # Create a temporary directory for our use.
    tmpdir_path = tempfile.mkdtemp()
    #FIXME!!!
    #tmpdir_path = os.getcwd()

    # Read in the distro file.
    try:
        jfile = open(ivars['DISTRO_FILE'])
    except (OSError, IOError) as err:
        _eprint("Error opening file %s: %s" % (ivars['DISTRO_FILE'], err))
        sys.exit(1)
    try:
        distro_json = json.load(jfile)
    except ValueError as err:
        _eprint("Error: Invalid JSON input in file %s: %s"
                % (ivars['DISTRO_FILE'], err))
        jfile.close()
        sys.exit(1)
    jfile.close()

    # Read in the build file.
    try:
        jfile = open(ivars['BUILD_FILE'])
    except (OSError, IOError) as err:
        _eprint("Error opening file %s: %s" % (ivars['BUILD_FILE'], err))
        sys.exit(1)
    try:
        build_json = json.load(jfile)
    except ValueError as err:
        _eprint("Error: Invalid JSON input in file %s: %s"
                % (ivars['BUILD_FILE'], err))
        jfile.close()
        sys.exit(1)
    jfile.close()

    # We need to validate the distro JSON data here, making sure we've
    # got everything we need.
    if not 'docker_stages' in distro_json:
        _eprint("Error: Missing 'docker_stages' data in %s."
                % ivars['DISTRO_FILE'])
        sys.exit(1)
    if not 'distro_package_installer' in distro_json:
        _eprint("Error: Missing 'distro_package_installer' data in %s."
                % ivars['DISTRO_FILE'])
        sys.exit(1)
    
    # We need to validate the build JSON data here, making sure we've
    # got everything we need.
    if not 'file_info' in build_json:
        _eprint("Error: Missing 'file_info' data in %s." % ivars['BUILD_FILE'])
        sys.exit(1)
    if not 'distro_version' in build_json:
        _eprint("Error: Missing 'distro_version' data in %s." % ivars['BUILD_FILE'])
        sys.exit(1)
    ivars['DVER'] = build_json['distro_version']

    # If we've got a distro-specific script needed to install
    # packages, copy it to the temporary directory, since type docker
    # 'COPY' directive only works on paths relative to the temporary
    # directory.
    if 'distro_package_installer' in distro_json:
        try:
            src_path = os.path.join(ivars['DATA_DIR'],
                                    distro_json['distro_package_installer'])
            shutil.copy(src_path, tmpdir_path)
        except (shutil.Error, IOError) as err:
            _eprint("Error: copy failed: %s" % err)
            sys.exit(1)

    if 'header' in distro_json['docker_stages']:
        # Now treat the data as a template, and substitute the
        # information we've got. Why aren't we using docker's 'ARG'
        # directive? There are places, like in 'FROM' directives, that
        # you can't use 'ARG' variables. So, we're rolling our own.
        orig_dockerfile_data = string.join(distro_json['docker_stages']['header'], '\n')
        orig_dockerfile_data += '\n'
        template = string.Template(orig_dockerfile_data)
        dockerfile_data = template.substitute(ivars)
        
    # Now add an item for each file to be installed.
    orig_install_data = string.join(distro_json['docker_stages']['install'],
                                    '\n')
    orig_install_data += '\n'
    template = string.Template(orig_install_data)
    for file_info in build_json['file_info']:
        ivars['NAME'] = file_info['name']
        ivars['PKG'] = file_info['pkg']
        ivars['BUILD_ID'] = file_info['build_id']
        dockerfile_data += template.substitute(ivars)

    if 'footer' in distro_json['docker_stages']:
        # See the 'header' discussion for why we're doing this.
        orig_dockerfile_data = string.join(distro_json['docker_stages']['footer'], '\n')
        orig_dockerfile_data += '\n'
        template = string.Template(orig_dockerfile_data)
        dockerfile_data += template.substitute(ivars)

    # Write the dockerfile data to a file.
    dockerfile_path = "%s/%s.docker" % (tmpdir_path, ivars['DOCKER_TAG'])
    tmpfile = open(dockerfile_path, "w")
    tmpfile.write(dockerfile_data)
    tmpfile.close()
    print("created file in %s\n" % tmpdir_path)

    # At this point we've created the docker file. Actually
    # build the docker container. Arguments:
    #
    #   -t TAG:  Repository names (and optionally with tags) to be
    #            applied to the resulting image in case of success.
    #   -f, --file=PATH/Dockerfile:  Path to the Dockerfile to use.
    #
    cmd = ("docker build -t %s -f %s %s"
           % (ivars['DOCKER_TAG'], dockerfile_path, tmpdir_path))
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
