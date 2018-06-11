# Note that this script was written to be executable by either version
# of python (checked by running pylint-2 and pylint-3 on it). Also
# note that the python version this script gets executed by is decided
# on by httpd/backends.cxx.

"""Build a docker file and container image based on a JSON template."""

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
    _eprint('Usage: %s [-v] --distro-file DISTRO_JSON_FILE'
            ' --build-file DATA_JSON_FILE --data-dir DATA_DIR'
            ' --dest-dir DEST_DIR'
            % sys.argv[0])
    sys.exit(1)

def _handle_command_line():
    import getopt

    verbose = 0
    ivars = {}

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 5:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v',
                                      ['distro-file=', 'build-file=',
                                       'data-dir=', 'dest-dir='])
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
        elif opt == '--dest-dir':
            ivars['DEST_DIR'] = value

    if len(pargs) != 0:
        _eprint("Extra argument found.")
        _usage()
    if 'DISTRO_FILE' not in ivars or 'BUILD_FILE' not in ivars \
       or 'DATA_DIR' not in ivars or 'DEST_DIR' not in ivars:
        _eprint("Arguments '--distro-file', '--build-file',"
                " '--data-dir', and '--dest-dir' are required.")
        _usage()
    return (verbose, ivars)

def _load_distro_file(distro_path):
    # Read in the distro file.
    try:
        jfile = open(distro_path)
    except (OSError, IOError) as err:
        _eprint("Error opening file %s: %s" % (distro_path, err))
        sys.exit(1)
    try:
        distro_json = json.load(jfile)
    except ValueError as err:
        _eprint("Error: Invalid JSON input in file %s: %s"
                % (distro_path, err))
        jfile.close()
        sys.exit(1)
    jfile.close()

    # We need to validate the distro JSON data here, making sure we've
    # got everything we need.
    if 'docker_stages' not in distro_json:
        _eprint("Error: Missing 'docker_stages' data in %s." % distro_path)
        sys.exit(1)
    if 'distro_package_installer' not in distro_json:
        _eprint("Error: Missing 'distro_package_installer' data in %s."
                % distro_path)
        sys.exit(1)
    return distro_json

def _load_build_file(build_path):
    # Read in the build file.
    try:
        jfile = open(build_path)
    except (OSError, IOError) as err:
        _eprint("Error opening file %s: %s" % (build_path, err))
        sys.exit(1)
    try:
        build_json = json.load(jfile)
    except ValueError as err:
        _eprint("Error: Invalid JSON input in file %s: %s"
                % (build_path, err))
        jfile.close()
        sys.exit(1)
    jfile.close()

    # We need to validate the build JSON data here, making sure we've
    # got everything we need.
    if 'file_info' not in build_json:
        _eprint("Error: Missing 'file_info' data in %s." % build_path)
        sys.exit(1)
    if 'distro_version' not in build_json:
        _eprint("Error: Missing 'distro_version' data in %s." % build_path)
        sys.exit(1)
    return build_json

def main():
    """Main function."""

    (verbose, ivars) = _handle_command_line()

    # Read the distro file.
    distro_json = _load_distro_file(ivars['DISTRO_FILE'])

    # Read the build file.
    build_json = _load_build_file(ivars['BUILD_FILE'])
    ivars['DVER'] = build_json['distro_version']

    # If we've got a distro-specific script needed to install
    # packages, copy it to the destination directory, since the docker
    # 'COPY' directive only works on paths relative to the destination
    # directory.
    if 'distro_package_installer' in distro_json:
        try:
            src_path = os.path.join(ivars['DATA_DIR'],
                                    distro_json['distro_package_installer'])
            shutil.copy(src_path, ivars['DEST_DIR'])
        except (shutil.Error, IOError) as err:
            _eprint("Error: copy failed: %s" % err)
            sys.exit(1)

    dockerfile_data = ''
    if 'header' in distro_json['docker_stages']:
        # Now treat the data as a template, and substitute the
        # information we've got. Why aren't we using docker's 'ARG'
        # directive? There are places, like in 'FROM' directives, that
        # you can't use 'ARG' variables. So, we're rolling our own.
        orig_data = '\n'.join(distro_json['docker_stages']['header'])
        orig_data += '\n'
        template = string.Template(orig_data)
        dockerfile_data += template.substitute(ivars)

    # Now add an item for each file to be installed.
    orig_data = '\n'.join(distro_json['docker_stages']['install'])
    orig_data += '\n'
    template = string.Template(orig_data)
    for file_info in build_json['file_info']:
        ivars['NAME'] = file_info['name']
        ivars['PKG'] = file_info['pkg']
        ivars['BUILD_ID'] = file_info['build_id']
        dockerfile_data += template.substitute(ivars)

    if 'footer' in distro_json['docker_stages']:
        # See the 'header' discussion for why we're doing this.
        orig_data = '\n'.join(distro_json['docker_stages']['footer'])
        orig_data += '\n'
        template = string.Template(orig_data)
        dockerfile_data += template.substitute(ivars)

    # Write the dockerfile data to a file.
    dockerfile_path = ("%s/base.docker" % ivars['DEST_DIR'])
    tmpfile = open(dockerfile_path, "w")
    tmpfile.write(dockerfile_data)
    tmpfile.close()
    print("created file in %s\n" % ivars['DEST_DIR'])

    # At this point we've created the docker file, so we're done.
    sys.exit(0)

if __name__ == '__main__':
    main()
