cmd_/home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc/.install := /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc ./include/uapi/scsi/fc fc_els.h fc_fs.h fc_gs.h fc_ns.h; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc ./include/scsi/fc ; /bin/sh scripts/headers_install.sh /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc ./include/generated/uapi/scsi/fc ; for F in ; do echo "\#include <asm-generic/$$F>" > /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc/$$F; done; touch /home/zhou/newsvn/buildroot/131/buildroot-2017.05/output/host/usr/arm-buildroot-linux-gnueabi/sysroot/usr/include/scsi/fc/.install