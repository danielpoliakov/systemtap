#! /usr/bin/python

"""Install specific versions of packages."""

# Here we want to make sure that we've got all the right versions of
# certain software installed.

from __future__ import print_function
import os
import os.path
import sys
import subprocess
import re

def which(cmd):
    """Find the full path of a command."""
    for path in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(os.path.join(path, cmd)):
            return os.path.join(path, cmd)

    return None

def _eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def _usage():
    """Display command-line usage."""
    _eprint("Usage: %s [-v] --name NAME --pkg PACKAGE --build_id BUILD_ID"
            % sys.argv[0])
    sys.exit(1)

class PkgSystem(object):
    "A class to hide the details of package management."
    __verbose = 0
    __distro_id = None
    __release = None
    __pkgr_path = None
    __pkgmgr_path = None
    __wget_path = None

    def __init__(self, verbose):
        __verbose = verbose

        #
        # Try to figure out what distro/release we've got. We might
        # have to do more later if necessary to figure out the
        # distro/release (like looking at /etc/redhat-release).
        #
        # Note that it isn't an error if we can't figure out the
        # distroy/release - we may not need that information.
        lsb_release = which("lsb_release")
        if lsb_release != None:
            try:
                self.__distro_id = subprocess.check_output([lsb_release, "-is"])
            except subprocess.CalledProcessError:
                pass
            try:
                self.__release = subprocess.check_output([lsb_release, "-rs"])
            except subprocess.CalledProcessError:
                pass

        #
        # Make sure we know the base package manager the system uses.
        self.__pkgr_path = which("rpm")
        if self.__pkgr_path is None:
            _eprint("Can't find the 'rpm' executable.")
            sys.exit(1)

        #
        # Find the package manager for this system.
        self.__pkgmgr_path = which("dnf")
        if self.__pkgmgr_path is None:
            self.__pkgmgr_path = which("yum")
        if self.__pkgmgr_path is None:
            _eprint("Can't find a package manager (either 'dnr' or 'yum').")
            sys.exit(1)

        #
        # See if we've got 'wget'. It isn't an error if we don't have
        # it since we may not need it.
        self.__wget_path = which("wget")

    def pkg_exists(self, pkg_nvr, pkg_build_id):
        """Return true if the package and its debuginfo exists."""
        if subprocess.call([self.__pkgr_path, "-qi", pkg_nvr]) != 0:
            return 0
        if len(pkg_build_id) == 0:
            if self.__verbose:
                print("Package %s already exists on the system." % pkg_nvr)
            return 1
        # Note we're looking for an exact match with a build id
        # here.
        build_id_path = '/usr/lib/debug/.build-id/' + pkg_build_id[:2] \
                        + '/' + pkg_build_id[2:]
        if os.path.exists(build_id_path):
            if self.__verbose:
                print("Package %s already exists on the system." % pkg_nvr)
            return 1
        return 0

    def pkg_install(self, pkg_nvr, pkg_build_id):
        """Install a package and its debuginfo."""
        if subprocess.call([self.__pkgmgr_path, 'install', '-y',
                            pkg_nvr]) != 0:
            return 0
        if len(pkg_build_id) == 0:
            if self.__verbose:
                print("Package %s installed." % pkg_nvr)
            return 1
        if subprocess.call([self.__pkgmgr_path, 'debuginfo-install',
                            '-y', pkg_nvr]) != 0:
            return 0

        # FIXME: What do we do here in the case where the debuginfo
        # install works, but the build ids don't match? sys.exit(1)
        if self.__verbose:
            print("Package %s and its debuginfo installed." % pkg_nvr)
        return 1

    def pkg_download_and_install(self, pkg_nvr, pkg_build_id):
        """Manually download and install a package."""
        # If we're not on Fedora, we don't know how to get the
        # package.
        if self.__wget_path is None or self.__distro_id is None \
           or self.__distro_id.lower() != "fedora":
            _eprint("Can't download package '%s'" % pkg_nvr)
            sys.exit(1)

        # FIXME: work on this later...
        _eprint("Can't download package '%s'" % pkg_nvr)
        sys.exit(1)

        # Build up the koji url. Koji urls look like:
        # http://kojipkgs.fedoraproject.org/packages/NAME/VER/RELEASE/ARCH/RPM_FILENAME

        #url = "http://kojipkgs.fedoraproject.org/packages/%s/%s/%s/%s/%s"

        # try downloading the package from koji, Fedora's build system.
        #rc = subprocess.call([self.__wget_path, ?]
        if self.__verbose:
            print("Package %s downloaded and installed." % pkg_nvr)
        return 1

def main():
    """Main function."""
    import getopt

    verbose = 0

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 4:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v', ['name=', 'pkg=', 'build_id='])
    except getopt.GetoptError as err:
        _eprint("Error: %s" % err)
        _usage()
    pkg_name = ''
    pkg_nvr = ''
    pkg_build_id = ''
    for (opt, value) in opts:
        if opt == '-v':
            verbose += 1
        elif opt == '--name':
            pkg_name = value
        elif opt == '--pkg':
            pkg_nvr = value
        elif opt == '--build_id':
            pkg_build_id = value
    if pargs:
        _usage()
    if len(pkg_name) == 0 or len(pkg_nvr) == 0 or len(pkg_build_id) == 0:
        _eprint("Error: '--name', '--pkg', and '--build_id' are required arguments.")
        _usage()

    packages = []
    packages.append([pkg_name, pkg_nvr, pkg_build_id])

    # If the package name is 'kernel', we've got to do some special
    # processing. We also want to install the matching kernel-devel
    # (along with the debuginfo).
    # 
    # Note that we have to handle/recognize kernel variants, like
    # 'kernel-PAE' or 'kernel-debug'.
    kernel_regexp = re.compile('^kernel(-\w+)?')
    match = kernel_regexp.match(pkg_name)
    if match:
        devel_name = pkg_name + '-devel'
        devel_nvr = re.sub(pkg_name, devel_name, pkg_nvr)
        packages.append([devel_name, devel_nvr, ''])

    pkgsys = PkgSystem(verbose)
    for (pkg_name, pkg_nvr, pkg_build_id) in packages:
        # Is the correct package version already installed?
        if pkgsys.pkg_exists(pkg_nvr, pkg_build_id):
            continue

        # Try using the package manager to install the package
        if pkgsys.pkg_install(pkg_nvr, pkg_build_id):
            continue

        # As a last resort, try downloading and installing the package
        # manually.
        if pkgsys.pkg_download_and_install(pkg_nvr, pkg_build_id):
            continue

        _eprint("Can't find package '%s'" % pkgname)
        sys.exit(1)

    if verbose:
        print("All packages installed.")
    sys.exit(0)

if __name__ == '__main__':
    main()
