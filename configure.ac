AC_INIT(nbdx, 0.1, libxio@accellio.org)

AC_PROG_INSTALL

runver=`uname -r`
kernelsrc=/lib/modules/${runver}/kernel
kernelbuild=/lib/modules/${runver}/build
kmoduledir=/lib/modules/${runver}/extra
xiodir=/opt/xio
KERNELMAKE_PARAMS=-I${xiodir}/include
XIOSYMS=${xiodir}/include/Module.symvers
AC_SUBST(kernelsrc)
AC_SUBST(kernelbuild)
AC_SUBST(kmoduledir)
AC_SUBST(KERNELMAKE_PARAMS)
AC_SUBST(XIOSYMS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
