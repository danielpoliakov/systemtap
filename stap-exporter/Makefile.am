# Makefile.am --- automake input file for systemtap man pages
## process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = no-dist foreign subdir-objects

# if we have python3
if HAVE_PYTHON3_PROBES

man8_MANS = stap-exporter.8

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)/systemtap/stap-exporter"
	$(MKDIR_P) "$(DESTDIR)$(prefix)/lib/systemd/system"
	$(INSTALL_DATA) $(srcdir)/stap-exporter.service "$(DESTDIR)$(prefix)/lib/systemd/system"

uninstall-local:
	rm -f "$(DESTDIR)$(prefix)/lib/systemd/system/stap-exporter.service"

sbin_SCRIPTS = stap-exporter

stap-exporter: $(srcdir)/stap-exporter.in
	sed -e "s#%sysconfdir%#$(sysconfdir)#g" < $< > $@

clean-local:
	rm -f stap-exporter

endif
