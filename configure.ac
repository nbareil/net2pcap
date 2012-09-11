AC_INIT([net2pcap], [0.2], [nico@chdir.org], [net2pcap], [http://github.com/nbareil/net2pcap/])
AC_PREREQ([2.59])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_ARG_ENABLE([sandbox],
              [ --disable-sandbox          do not use SECCOMP sandbox],
              [sandbox=${enableval}], [sandbox=auto])

have_seccomp=no

if test "x${sandbox}" != xno; then
    AC_SEARCH_LIBS([seccomp_init], [seccomp], [have_seccomp=yes])
    AC_CHECK_HEADERS([seccomp.h])
fi

if test "x${sandbox}" = xyes && test "x${have_seccomp}" != xyes; then
   AC_MSG_ERROR([
   --------------------------------------------
   Unable to find libseccomp. Abording.
   --------------------------------------------
   ])
fi

AC_PROG_CC
AC_OUTPUT
