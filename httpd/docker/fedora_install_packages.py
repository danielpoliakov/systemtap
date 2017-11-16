#! /usr/bin/python

"""Install specific versions of packages."""

# Here we want to make sure that we've got all the right versions of
# certain software installed.
#
# FIXME 1: Should we always also automatically install debuginfo for
# each package or should it be configurable?
#
# FIXME 2: Instead of command line args, we should probably get the
# list of packages from a file of some sort.
#
# FIXME 3: Besides NVRs, we'll also need build ids (which is one
# reason why FIXME 2 makes sense).

from __future__ import print_function
import os
import os.path
import sys
import subprocess

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
    _eprint("Usage: %s [-v] PACKAGE1..." % sys.argv[0])
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
        #
        # FIXME: If we want to support Ubuntu-type distros later,
        # we'll also need to look for dpkg.
        self.__pkgr_path = which("rpm")
        if self.__pkgr_path is None:
            _eprint("Can't find the 'rpm' executable.")
            sys.exit(1)

        #
        # Find the package manager for this system.
        #
        # FIXME: If we want to support Ubuntu-type distros later,
        # we'll also need to look for apt-get.
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

    def pkg_exists(self, pkg):
        """Return true if the package exists."""
        if not subprocess.call([self.__pkgr_path, "-qi", pkg]):
            if self.__verbose:
                print("Package %s already exists on the system." % pkg)
            return 1
        return 0

    def pkg_install(self, pkg):
        """Install a package."""
        if not subprocess.call([self.__pkgmgr_path, "install", "-y", pkg]):
            if self.__verbose:
                print("Package %s installed." % pkg)
            return 1
        return 0

    def pkg_download_and_install(self, pkg):
        """Manually download and install a package."""
        # If we're not on Fedora, we don't know how to get the
        # package.
        if self.__wget_path is None or self.__distro_id is None \
           or self.__distro_id.lower() != "fedora":
            _eprint("Can't download package '%s'" % pkg)
            sys.exit(1)

        # FIXME: work on this later...
        _eprint("Can't download package '%s'" % pkg)
        sys.exit(1)

        # Build up the koji url. Koji urls look like:
        # http://kojipkgs.fedoraproject.org/packages/NAME/VER/RELEASE/ARCH/RPM_FILENAME

        #url = "http://kojipkgs.fedoraproject.org/packages/%s/%s/%s/%s/%s"

        # try downloading the package from koji, Fedora's build system.
        #rc = subprocess.call([self.__wget_path, ?]
        if self.__verbose:
            print("Package %s downloaded and installed." % pkg)
        return 1

def main():
    """Main function."""
    import getopt

    verbose = 0

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 2:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v')
    except getopt.GetoptError as err:
        _eprint("Error: %s" % err)
        _usage()
    for (opt, dummy) in opts:
        if opt == '-v':
            verbose += 1
    if not pargs:
        _usage()

    # For each package:
    pkgsys = PkgSystem(verbose)
    for pkgname in pargs:
        # Is the correct package version already installed?
        if pkgsys.pkg_exists(pkgname):
            continue

        # Try using the package manager to install the package
        if pkgsys.pkg_install(pkgname):
            continue

        # As a last resort, try downloading and installing the package
        # manually.
        if pkgsys.pkg_download_and_install(pkgname):
            continue

        _eprint("Can't find package '%s'" % pkgname)
        sys.exit(1)

    if verbose:
        print("All packages installed.")
    sys.exit(0)

if __name__ == '__main__':
    main()
