cmd_/home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi/.install := /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi ./include/uapi/linux/hsi cs-protocol.h hsi_char.h; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi ./include/linux/hsi ; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi ./include/generated/uapi/linux/hsi ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi/$$F; done; touch /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/linux/hsi/.install