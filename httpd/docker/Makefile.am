AUTOMAKE_OPTIONS = no-dist foreign subdir-objects

JSON_FILES_DEST=$(DESTDIR)$(pkgdatadir)/httpd/docker

# Any script in the following variable will get byte-compiled at
# install time.
pkglibexecdocker_PYTHON =

pkglibexecdockerdir = $(pkglibexecdir)/httpd/docker

if HAVE_HTTP_SUPPORT

pkglibexecdocker_PYTHON += stap_build_docker_container.py

install-data-local:
	$(MKDIR_P) $(JSON_FILES_DEST)
	for f in $(srcdir)/*.json; do \
		$(INSTALL_DATA) "$$f" "$(JSON_FILES_DEST)"; \
	done
endif
