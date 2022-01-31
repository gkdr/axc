prefix=@_AXC_PKGCONF_PREFIX@
exec_prefix=@_AXC_PKGCONF_EXEC_PREFIX@
libdir=@_AXC_PKGCONF_LIBDIR@
includedir=@_AXC_PKGCONF_INCLUDEDIR@

Name: libaxc
Version: @PROJECT_VERSION@
Description: client library for libsignal-protocol-c
URL: https://github.com/gkdr/axc
Requires: libsignal-protocol-c
Requires.private: glib-2.0 libgcrypt sqlite3
Cflags: -I${includedir}/axc
Libs: -L${libdir} -laxc
