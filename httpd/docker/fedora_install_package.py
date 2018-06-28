#! /usr/bin/python
#
# Note that the above interpreter choice is correct -
# '/usr/bin/python'. It isn't '/usr/bin/python2' or
# '/usr/bin/python3'. But, this is OK. This script is run in a
# container, and we won't know which python we're executing (or even
# which will be installed), but we should be assured of one or the
# other. This script was written to be executable by either version of
# python (checked by running pylint-2 and pylint-3 on it).

"""Install specific versions of packages."""

# Here we want to make sure that we've got all the right versions of
# certain software installed.

from __future__ import print_function
import os
import os.path
import sys
import subprocess
import re
import platform
import getopt
import shutil


# split_nvra() is based on rpmUtils.miscutils.splitFilename() from
# yum. Why not just use that? There isn't a python3 version supported
# and yum is going away (at some point) from Fedora.
def split_nvra(pkg_nvr):
    """
    Pass in a standard style rpm name

    Returns a name, version, release, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
    """

    # If we've got a build id link target, it will end with
    # '.debug'. Remove it.
    if pkg_nvr[-6:] == '.debug':
        pkg_nvr = pkg_nvr[:-6]

    arch_index = pkg_nvr.rfind('.')
    arch = pkg_nvr[arch_index+1:]

    rel_index = pkg_nvr[:arch_index].rfind('-')
    rel = pkg_nvr[rel_index+1:arch_index]

    ver_index = pkg_nvr[:rel_index].rfind('-')
    ver = pkg_nvr[ver_index+1:rel_index]

    name = pkg_nvr[:ver_index]
    return name, ver, rel, arch

def which(cmd):
    """Find the full path of a command."""
    for path in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(os.path.join(path, cmd)):
            return os.path.join(path, cmd)

    return None

def _eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def build_id_symlink_is_valid(bid_path):
    """Check if a build id symlink is valid."""
    symlink_exists = os.path.exists(bid_path) and os.path.islink(bid_path)
    bid_target = ''
    if symlink_exists:
        bid_target = os.readlink(bid_path)
        if not os.path.isabs(bid_target):
            bid_target = \
                os.path.abspath(os.path.join(os.path.dirname(bid_path),
                                             bid_target))
        if not os.path.exists(bid_target) \
           or os.path.islink(bid_target):
            symlink_exists = 0
    return symlink_exists, bid_target

class PkgSystem(object):
    "A class to hide the details of package management."
    # pylint: disable=too-many-instance-attributes
    __verbose = 0
    __distro_id = None
    __release = None
    __pkgr_path = None
    __pkgmgr_path = None
    __using_dnf = 0
    __wget_path = None
    __local_repo_path = ''
    __local_rpm_dir = ''

    def __init__(self, verbose):
        self.__verbose = verbose

        #
        # Try to figure out what distro/release we've got. We might
        # have to do more later if necessary to figure out the
        # distro/release (like looking at /etc/redhat-release).
        #
        # Note that it isn't an error if we can't figure out the
        # distro/release - we may not need that information.
        lsb_release = which("lsb_release")
        if lsb_release != None:
            try:
                if self.__verbose:
                    print("Running: %s" % [lsb_release, "-is"])
                self.__distro_id = subprocess.check_output([lsb_release, "-is"])
                self.__distro_id = self.__distro_id.strip()
            except subprocess.CalledProcessError:
                pass
            try:
                if self.__verbose:
                    print("Running: %s" % [lsb_release, "-rs"])
                self.__release = subprocess.check_output([lsb_release, "-rs"])
                self.__release = self.__release.strip()
            except subprocess.CalledProcessError:
                pass
        if self.__distro_id is None:
            self.__distro_id = platform.linux_distribution()[0]
        if self.__release is None:
            self.__release = platform.linux_distribution()[1]

        #
        # Make sure we know the base package manager the system uses.
        self.__pkgr_path = which("rpm")
        if self.__pkgr_path is None:
            _eprint("Can't find the 'rpm' executable.")
            sys.exit(1)

        #
        # Find the package manager for this system.
        self.__pkgmgr_path = which("dnf")
        self.__debuginfo_install = [self.__pkgmgr_path, 'debuginfo-install']
        self.__using_dnf = 1
        if self.__pkgmgr_path is None:
            self.__pkgmgr_path = which("yum")
            self.__debuginfo_install = [which('debuginfo-install')]
            self.__using_dnf = 0
        if self.__pkgmgr_path is None:
            _eprint("Can't find a package manager (either 'dnr' or 'yum').")
            sys.exit(1)

        #
        # See if we've got 'wget'. It isn't an error if we don't have
        # it since we may not need it.
        self.__wget_path = which("wget")

    def build_id_is_valid(self, name, build_id):
        """Return true if the 'name' matches the build id."""
        # If we don't have a build id, pretend it matched.
        if build_id == '':
            return 1
        # First, make sure the build id symbolic link exists. This has
        # to be an exact match. Note that Centos build id symbolic
        # links don't end in '.debug', Fedora build id symbolic links
        # do. Handle both.
        bid_path = '/usr/lib/debug/.build-id/' + build_id[:2] \
            + '/' + build_id[2:]
        (symlink_exists, bid_target) = build_id_symlink_is_valid(bid_path)
        if not symlink_exists:
            bid_path = '/usr/lib/debug/.build-id/' + build_id[:2] \
                + '/' + build_id[2:] + '.debug'
            (symlink_exists, bid_target) = build_id_symlink_is_valid(bid_path)
        if not symlink_exists:
            if self.__verbose:
                print("Build id %s doesn't exist." % build_id)
            return 0

        # Now we know the build id exists. But, does it point to the
        # correct file? Note that we're comparing basenames here. Why?
        # (1) The kernel doesn't really have a "path". (2)
        # "/usr/bin/FOO" is really the same file as "/bin/FOO"
        # (UsrMove feature).
        sym_target = os.path.basename(bid_target)
        if name == 'kernel':
            name = 'vmlinux'
        else:
            name = os.path.basename(name)
        matchp = (sym_target == name)
        if not matchp:
            # On Fedora 28, the link doesn't point to "FOO", but
            # "FOO-V-R.A.debug".
            pkg_details = split_nvra(sym_target)
            if pkg_details[0] == name:
                matchp = 1
        if not matchp:
            if self.__verbose:
                print("Build id %s doesn't match '%s'." % (build_id, name))
            return 0
        return 1

    def pkg_exists(self, pkg_nvr):
        """Return true if the package and its debuginfo exists."""
        if self.__verbose:
            print("Running: %s" % [self.__pkgr_path, '-qi', '--quiet',
                                   pkg_nvr])
        if subprocess.call([self.__pkgr_path, '-qi', '--quiet', pkg_nvr]) != 0:
            return 0
        return 1

    def pkg_install(self, pkg_nvr, build_id):
        """Install a package and its debuginfo."""
        if not self.pkg_exists(pkg_nvr):
            # Why are we using the "noscripts" option here? Background
            # - building a Fedora 28 container on a Centos 7 host. On
            # a kernel install, the Fedora kernel rpm %post script ran
            # "dracut" to create a new initrd. The dracut command hit
            # an error, then proceeded to spew lots of errors and
            # ended up deleting /tmp in the container. So, to avoid
            # this, we won't run %pre/%post rpm scripts (which
            # hopefully shouldn't be needed anyway). If the %pre/%post
            # scripts end up being needed, we could only use
            # "noscripts" when installing a kernel.
            #
            # If we're using dnf, add the '--allowerasing' option so that
            # we can override conflicting packages.
            cmd = [self.__pkgmgr_path, 'install', '-y', '--quiet'] \
                + (['--allowerasing'] if self.__using_dnf else []) \
                + ['--setopt=tsflags=noscripts', pkg_nvr]
            if self.__verbose:
                print("Running: %s" % cmd)
            if subprocess.call(cmd) != 0:
                return 0

        # If we don't have a build id, we don't need to install
        # debuginfo.
        if build_id == '':
            return 1

        # Here we're assuming the debuginfo package doesn't already exist.
        cmd = self.__debuginfo_install + ['-y', '--quiet', pkg_nvr]
        if self.__verbose:
            print("Running: %s" % cmd)
        if subprocess.call(cmd) != 0:
            return 0
        # 'dnf debuginfo' has a *really* annoying habit of not
        # installing the exact version you asked for if the version
        # you asked for isn't available. So, make sure we actually
        # installed the right debuginfo package.
        pkg_details = split_nvra(pkg_nvr)
        debuginfo_nvr = (pkg_details[0] + '-debuginfo-' + pkg_details[1]
                         + '-' + pkg_details[2] + '.' + pkg_details[3])
        if not self.pkg_exists(debuginfo_nvr):
            # The wrong debuginfo package got installed. Try to remove
            # it.
            debuginfo_wildcard = pkg_details[0] + '-debuginfo-*'
            cmd = [self.__pkgmgr_path, 'remove', '-y',
                   '--setopt=tsflags=noscripts', debuginfo_wildcard]
            if self.__verbose:
                print("Running: %s" % cmd)
            subprocess.call(cmd)
            return 0
        return 1

    def pkg_download_and_install(self, pkg_nvr, build_id):
        """Manually download and install a package."""
        # If we're not on Fedora, we don't know how to get the
        # package.
        if self.__wget_path is None or self.__distro_id is None \
           or self.__distro_id.lower() != "fedora":
            _eprint("Can't download package '%s'" % pkg_nvr)
            return 0

        # Try downloading the package from koji, Fedora's build system.
        #
        # Build up the koji url. Koji urls look like:
        # http://kojipkgs.fedoraproject.org/packages/NAME/VER/RELEASE/ARCH/
        pkg_details = split_nvra(pkg_nvr)
        koji_url = ("http://kojipkgs.fedoraproject.org/packages/%s/%s/%s/%s"
                    % (pkg_details[0], pkg_details[1], pkg_details[2],
                       pkg_details[3]))
        _eprint("URL: '%s'" % koji_url)

        # Download the entire arch directory. Here's a description of
        # wget's arguments:
        #
        #   --quiet: Don't display progress.
        #   -nH: No host directories (i.e. get rid of the host name in
        #        the download directory name).
        #   --cut-dirs=4: Ignore 4 directory components.
        #   -r: Turn on recursive retrieving.
        #   -l 1: Maximum recursion depth is 1.
        #
        if self.__verbose:
            print("Running: %s" % ['wget', '--quiet', '-nH', '--cut-dirs=4',
                                   '-r', '-l', '1', koji_url])
        if subprocess.call(['wget', '--quiet', '-nH', '--cut-dirs=4',
                            '-r', '-l', '1', koji_url]) != 0:
            _eprint("Can't download package '%s'" % pkg_nvr)
            return 0

        # OK, now we've got a directory which contains all the RPMs
        # for package 'foo'. We can't just do a "dnf install RPM",
        # because (for example) the 'kernel' RPM requires the
        # 'kernel-core' and 'kernel-firmware' RPMs. We might be able
        # to install all the RPMs we just downloaded, but besides
        # being overkill, it is theoretically possible that they might
        # conflict somehow.
        #
        # So, instead we'll create a local repo that then yum/dnf can
        # use when looking for RPMs.

        # First create the repo file.
        self.__local_repo_path = '/etc/yum.repos.d/local.repo'
        self.__local_rpm_dir = '/root/%s' % pkg_details[3]
        if not os.path.exists(self.__local_repo_path):
            repo_file = open(self.__local_repo_path, 'w')
            repo_file.write('[local]\n')
            repo_file.write('name=Local repository\n')
            repo_file.write('baseurl=file://%s\n' % self.__local_rpm_dir)
            repo_file.write('enabled=1\n')
            repo_file.write('gpgcheck=0\n')
            repo_file.write('type=rpm\n')
            repo_file.close()

        # Next run 'createrepo_c' on the directory.
        if self.__verbose:
            print("Running: %s" % ['createrepo_c', '--quiet', self.__local_rpm_dir])
        if subprocess.call(['createrepo_c', '--quiet', self.__local_rpm_dir]) != 0:
            _eprint("Can't run createrepo_c")
            return 0

        # At this point we should be set up to let the package manager
        # install the package.
        return self.pkg_install(pkg_nvr, build_id)

    def cleanup(self):
        """Perform cleanup (if necessary)."""
        if self.__local_repo_path:
            os.remove(self.__local_repo_path)
        if self.__local_rpm_dir:
            shutil.rmtree(self.__local_rpm_dir)

def _usage():
    """Display command-line usage."""
    _eprint("Usage: %s [-v] --name NAME --pkg PACKAGE --build_id BUILD_ID"
            % sys.argv[0])
    sys.exit(1)

def _handle_command_line():
    """Process command line."""
    verbose = 0
    name = ''
    pkg_nvr = ''
    build_id = ''

    # Make sure the command line looks reasonable.
    if len(sys.argv) < 4:
        _usage()
    try:
        (opts, pargs) = getopt.getopt(sys.argv[1:], 'v', ['name=', 'pkg=', 'build_id='])
    except getopt.GetoptError as err:
        _eprint("Error: %s" % err)
        _usage()
    for (opt, value) in opts:
        if opt == '-v':
            verbose += 1
        elif opt == '--name':
            name = value
        elif opt == '--pkg':
            pkg_nvr = value
        elif opt == '--build_id':
            build_id = value
    if pargs:
        _usage()
    if not name or not pkg_nvr or not build_id:
        _eprint("Error: '--name', '--pkg', and '--build_id' are required arguments.")
        _usage()
    return (verbose, name, pkg_nvr, build_id)

def main():
    """Main function."""
    (verbose, name, pkg_nvr, build_id) = _handle_command_line()

    # Make sure we're in /root.
    os.chdir('/root')

    packages = []
    packages.append([name, pkg_nvr, build_id])

    # If the package name is 'kernel', we've got to do some special
    # processing. We also want to install the matching kernel-devel
    # (along with the debuginfo).
    #
    # Note that we have to handle/recognize kernel variants, like
    # 'kernel-PAE' or 'kernel-debug'.
    kernel_regexp = re.compile(r'^kernel(-\w+)?')
    match = kernel_regexp.match(name)
    if match:
        devel_name = name + '-devel'
        devel_nvr = re.sub(name, devel_name, pkg_nvr)
        # Notice we're not including the build id. When there's no
        # build id, build_id_is_valid() returns a 1.
        packages.append([devel_name, devel_nvr, ''])

    pkgsys = PkgSystem(verbose)
    for (name, pkg_nvr, build_id) in packages:
        # Try using the package manager to install the package and its
        # debuginfo.
        if pkgsys.pkg_install(pkg_nvr, build_id):
            # The package and its debuginfo exist. Does the build id
            # match?
            if pkgsys.build_id_is_valid(name, build_id):
                continue
            # If the package and its debuginfo exists, but the build
            # ids don't match, we're done.
            _eprint("Package '%s' is installed, but the build id"
                    " doesn't match" % pkg_nvr)
            pkgsys.cleanup()
            sys.exit(1)

        # As a last resort, try downloading and installing the package
        # manually.
        if pkgsys.pkg_download_and_install(pkg_nvr, build_id):
            # The package and its debuginfo exist. Does the build id
            # match?
            if pkgsys.build_id_is_valid(name, build_id):
                continue
            # If the package and its debuginfo exists, but the build
            # ids don't match, we're done.
            _eprint("Package '%s' is installed, but the build id"
                    " doesn't match" % pkg_nvr)
            pkgsys.cleanup()
            sys.exit(1)

        # If the package manager couldn't install the package, and we
        # couldn't download and install the package manually, we're
        # done.
        _eprint("Can't find package '%s'" % pkg_nvr)
        sys.exit(1)

    if verbose:
        print("All packages installed.")

    # Perform cleanup, if needed.
    pkgsys.cleanup()
    sys.exit(0)

if __name__ == '__main__':
    main()
