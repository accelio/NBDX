# this is example-file: configure.ac

# initial information about the project
AC_INIT([nbdx_server],[1.0],[nbdx@accelio.org])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE

# Checks for language
AC_LANG_C

# Checks for programs
LT_INIT
AC_PROG_LIBTOOL

# check for C compiler and the library compiler
AC_PROG_CC
AM_PROG_CC_C_O

# automake initialisation (mandatory) and check for minimal automake API version 1.9
AM_INIT_AUTOMAKE([1.11])
AM_SILENT_RULES([yes])

# use the C compiler for the following checks
AC_LANG([C])

# Checks for header files.
AC_CHECK_HEADERS([infiniband/verbs.h rdma/rdma_cma.h],
		 [mypj_found_verbs_headers=yes; break;])

AC_CHECK_HEADERS([numa.h],
		 [mypj_found_numa_headers=yes; break;])


AS_IF([test "x$mypj_found_verbs_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the infiniband header files])])
AS_IF([test "x$mypj_found_numa_headers" != "xyes"],
      [AC_MSG_ERROR([Unable to find the numactl-devel header files])])
# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

AC_CHECK_LIB(numa, numa_available)

##########################################################################
# perf support
##########################################################################
# usage: ./configure --enable-perf=yes
#
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([perf],
	      [AS_HELP_STRING([--enable-perf],
			      [enable perf profiling])],
			       [enable_perf="$enableval"],
			       [enable_perf=no])
AC_MSG_RESULT([$enable_perf])

if test "$enable_perf" = "yes"; then
	AM_CFLAGS="$AM_CFLAGS -fno-omit-frame-pointer"
fi

##########################################################################
# debug compilation support
##########################################################################
# usage: ./configure --enable-debug=yes
#
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
	      [AS_HELP_STRING([--enable-debug],
			      [enable debug data generation])],
			       [enable_debug="$enableval"],
			       [enable_debug=no])
AC_MSG_RESULT([$enable_debug])

if test "$enable_debug" = "yes"; then
	AC_DEFINE([DEBUG],[],[Debug Mode])
	AM_CFLAGS="$AM_CFLAGS -g -ggdb -Wall -Werror -Wdeclaration-after-statement \
		   -fno-omit-frame-pointer -O0 -D_REENTRANT -D_GNU_SOURCE"
else
	AC_DEFINE([NDEBUG],[],[No-debug Mode])
	AM_CFLAGS="$AM_CFLAGS -g -ggdb -Wall -Werror -Wpadded -Wdeclaration-after-statement \
		  -O3 -D_REENTRANT -D_GNU_SOURCE"
fi

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")


subdirs2="src/";

##########################################################################

##########################################################################
# add version.c uses strings to get GIT hash version
##########################################################################
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z ${GITHEAD} ; then
		GITHEAD=`git rev-parse HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD=${GITHEAD}-dirty
		fi
else
	GITHEAD=
fi
echo "const char NBDX_SERVER_GIT_HEAD@<:@@:>@ = \"GIT_VERSION: $GITHEAD\";" \/\* for use with strings \*\/ >version.c
echo "const char NBDX_SERVER_GIT_HEAD_STRING@<:@@:>@ = \"$GITHEAD\";" >>version.c

AC_MSG_CHECKING([for git head])
AC_MSG_RESULT([$GITHEAD])
AC_DEFINE_UNQUOTED([NBDX_SERVER_GITHEAD], ["$GITHEAD"], [Git commit used to build nbdx server])

# distribute additional compiler and linker flags
# --> set these variables instead of CFLAGS or LDFLAGS
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])
AC_SUBST([subdirs2])


# files to generate via autotools (.am or .in source files)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

# generate the final Makefile etc.
AC_OUTPUT

