import hashlib
import os
import glob

listWithNotAccurate =( "/boot/vmlinuz-*",
"/boot/initrd.img-*",
"/boot/grub/*",
"/lib/modules/*/misc/digsig_verif.ko",
"/lib/modules/*/misc/parsec.ko",
"/lib/modules/*/misc/parsec-cifs.ko")

directoryGlobal =[
    "/boot/grub/grub.conf",
    "/etc/astra_license",
    "/etc/nsswitch.conf",
    "/etc/pam.d/fly-dm",
    "/etc/pam.d/fly-dm-np",
    "/etc/pam.d/login",
    "/etc/pam.d/passwd",
    "/etc/pam.d/su",
    "/etc/pam.d/sumac.xauth",
    "/etc/pam.d/xrdp-sesman",
    "/etc/resolv.conf",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/network/interfaces",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/samba/smb.conf",
    "/etc/apache2/apache2.conf"
    ]


for file in listWithNotAccurate:
    found = glob.glob(file)
    for path in found:
        directoryGlobal.append(path)

directoryImportant = {}

for peace in directoryGlobal:
    if os.path.isfile(peace):
        try:
            with open(peace, "rb") as file:
                toBinary = file.read()
            directoryImportant[peace] = hashlib.sha256(toBinary).hexdigest()
        except FileNotFoundError:
                print("Error of found")

#для пунктов 1-4 из отчета по диску

directoryMBR=[]

directoryPBR = []

dev_PBR = ["/dev/sd?", "/dev/vd?", "/dev/nvme?n?"]
for file in dev_PBR:
    found = glob.glob(file)
    for path in found:
        directoryMBR.append(path)

for disk in directoryMBR:
    if "nvme" in disk:
        pattern = f"{disk}p*"
    else:
        pattern = f"{disk}[0-9]*"
    for part in glob.glob(pattern):
        directoryPBR.append(part)


for directory in directoryMBR:
    if os.path.isfile(directory):
        try:
            with  open(directory, "rb") as file:
                file.seek(0)
                peace = file.read(512)
                directoryImportant[f"{directory}_MBR"] = hashlib.sha256(peace).hexdigest()
                file.seek(512)
                interval = file.read(512*63)
                directoryImportant[f"{directory}_1_to_63_sectors"] = hashlib.sha256(interval).hexdigest()
        except Exception as e:
            print(f"Error of found 1-4:{e}")

for directory in directoryPBR:
    if os.path.isfile(directory):
        try:
            with open(directory, "rb") as file:
                file.seek(0)
                pbr = file.read(512)
                directoryImportant[f"{directory}_PBR"] = hashlib.sha256(pbr).hexdigest()
        except Exception as e:
            print(f"Error of found PBR:{e}")


esp_files = glob.glob("/boot/efi**/*", recursive=True)
for esp in esp_files:
    if os.path.isfile(esp):
        try:
            with open(esp, "rb") as file:
                read = file.read()
                directoryImportant[f"{esp}"] = hashlib.sha256(read).hexdigest()
        except Exception as e:
            print(f"Error of found ESP:{e}")









