AUTOMAKE_OPTIONS = no-dist foreign subdir-objects

pkgdatadockerdir = $(DESTDIR)$(pkgdatadir)/httpd/docker

# Any file in the following variable will get installed to
# $(pkgdatadockerdir).
pkgdatadocker_DATA =

# Any script in the following variable will get byte-compiled at
# install time.
pkglibexecdocker_PYTHON =

pkglibexecdockerdir = $(DESTDIR)$(pkglibexecdir)/httpd/docker

if HAVE_HTTP_SUPPORT

# Why aren't we putting fedora_install_package.py into
# pkgdatadocker_PYTHON? fedora_install_package.py *is* a python
# script, but it will only be run inside docker containers, never on
# the host system. So, there isn't much point in compiling the script
# for the current system.
pkgdatadocker_DATA += fedora_install_package.py

# Make sure all the JSON files get installed.
pkgdatadocker_DATA += $(wildcard $(srcdir)/*.json)

pkglibexecdocker_PYTHON += stap_build_docker_file.py

endif
