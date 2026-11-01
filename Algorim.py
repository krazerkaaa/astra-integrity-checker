#import hashlib


directory_vmlinuz = {}

directory_initrd_img = {}

directory_boot_grub_ = {}

directory_lib_modules_misc_parsec_ko = {}

directory_lib_modules_misc_disig_verif_ko = {}

directory_lib_modules_misc_parsec_cifs_ko = {}

directoryImportant = {}

directoryWithGoodWay = \
    {
    "/boot/grub/grub.conf": 0,
    "/etc/astra_license": 0,
    "/etc/nsswitch.conf ": 0,
    "/etc/pam.d/fly-dm": 0,
    "/etc/pam.d/fly-dm-np": 0,
    "/etc/pam.d/login ": 0,
    "/etc/pam.d/passwd": 0,
    "/etc/pam.d/su": 0,
    "/etc/pam.d/sumac.xauth": 0,
    "/etc/pam.d/xrdp-sesman": 0,
    "/etc/resolv.conf": 0,
    "/etc/hosts.allow": 0,
    "/etc/hosts.deny": 0,
    "/etc/network/interfaces": 0,
    "/etc/ssh/sshd_config": 0,
    "/etc/hosts": 0,
    "/etc/samba/smb.conf": 0,
    "/etc/apache2/apache2.conf": 0
    }
lend = len(directoryImportant)
for i in range(0, lend):
    print("Directory: " + directoryWithGoodWay[i])
