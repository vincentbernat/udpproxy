#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(udpproxy, 0.2, bernat@luffy.cx)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])
AC_CONFIG_SRCDIR([src/proxy.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([nfnetlink], [nfnl_fd], [],
        [AC_MSG_NOTICE([*** without nfnetlink library, only client support will be enabled])
         AC_DEFINE([CLIENT_ONLY], 1, [Only compile client support])])
AC_CHECK_LIB([netfilter_queue], [nfq_open], [],
        [AC_MSG_NOTICE([*** without netfilter-queue, only client support will be enabled])
         AC_DEFINE([CLIENT_ONLY], 1, [Only compile client support])])
AC_CHECK_LIB([event], [event_set], [],
	[AC_MSG_ERROR([*** libevent was not found])])

# Checks for header files.
AC_CHECK_HEADERS([sys/tree.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.

AC_DEFINE([NFQ_PACKET_BUFFER_SIZE],4096,[Define the size of NFQ buffer])

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 src/Makefile])
AC_OUTPUT
