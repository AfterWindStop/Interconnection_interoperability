cmd_/home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi/.install := /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi ./include/uapi ; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi ./include ; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi ./include/generated/uapi ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi/$$F; done; touch /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/uapi/.install