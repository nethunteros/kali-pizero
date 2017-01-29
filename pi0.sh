#!/bin/bash
#
# Kali Linux on Raspberry Pi Zero (ARM) by Binkyear (binkybear@nethunter.com)
#
# * Not an official Kali Linux image but modified for my needs *
# * May be useful to others *
#
# * OTG Connection help
# * https://learn.adafruit.com/turning-your-raspberry-pi-zero-into-a-usb-gadget/ethernet-gadget
# 
# Included:
#
# * Geneate SSH Keys on first boot
# * XFCE4/Bash Tweaks from G0tMi1k and others
#       > https://github.com/g0tmi1k/os-scripts/blob/master/kali-rolling.sh
# * Change default lock screen
# * rpi-config to allow you to expand rootfs
# * Wireless packages
# * VPN Packages
# * MITM Packages
# * re4son's PI  kernel
#       > re4son: https://whitedome.com.au/re4son/sticky-fingers-kali-pi/#Vanilla
#       > github: https://github.com/re4son/
#
#################
# MODIFY THESE  #
#################

COMPRESS=false       # Compress output file with XZ (useful for release images)

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit
fi

basedir=`pwd`/rpi0-kali             # OUTPUT FOLDER
architecture="armel"                # DEFAULT ARCH FOR RPI
DIRECTORY=`pwd`/kali-$architecture  # CHROOT FS FOLDER
TOPDIR=`pwd`                        # CURRENT FOLDER
VERSION=$1

# TOOLCHAIN
#export PATH=${PATH}:`pwd`/gcc-arm-linux-gnueabihf-4.7/bin

# BUILD THE KALI FILESYSTEM

function build_chroot(){

if [ ! -f /usr/share/debootstrap/scripts/kali-rolling ]; then
    #
    # For those not building on Kali
    #
    echo "Missing kali from debootstrap, downloading it"

    curl "http://git.kali.org/gitweb/?p=packages/debootstrap.git;a=blob_plain;f=scripts/kali;hb=refs/heads/kali/master" > /usr/share/debootstrap/scripts/kali
    ln -s /usr/share/debootstrap/scripts/kali /usr/share/debootstrap/scripts/kali-rolling
fi

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="e2fsprogs initramfs-tools kali-defaults kali-menu parted sudo usbutils bash-completion dbus cowsay"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali kali-root-login lightdm network-manager network-manager-gnome xserver-xorg-video-fbdev xserver-xorg xinit"
xfce4="gtk3-engines-xfce lightdm-gtk-greeter-settings xfconf kali-desktop-xfce xfce4-settings xfce4 xfce4-mount-plugin xfce4-notifyd xfce4-places-plugin xfce4-appfinder"
tools="ethtool hydra john libnfc-bin mfoc nmap passing-the-hash php-cli sqlmap usbutils winexe tshark"
services="openssh-server tightvncserver dnsmasq hostapd bridge-utils isc-dhcp-server dsniff screen"
extras="unzip unrar curl firefox-esr xfce4-terminal wpasupplicant florence tcpdump dnsutils gcc build-essential"
wireless="aircrack-ng cowpatty python-dev kismet wifite pixiewps wireless-tools wicd-curses"
vpn="openvpn network-manager-openvpn network-manager-pptp network-manager-vpnc network-manager-openconnect network-manager-iodine"
g0tmi1k="tmux ipcalc sipcalc psmisc htop gparted tor hashid p0f msfpc exe2hexbat windows-binaries thefuck burpsuite"

# kernel sauces take up space yo.
size=7000 # Size of image in megabytes

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras} ${xfce4} ${vpn}"

# Full
#packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras} ${mitm} ${wireless} ${xfce4} ${vpn} ${g0tmi1k}"

# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

# Make output folder
mkdir -p ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

echo "[+] Beginning SECOND stage"
LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage

echo "[+] Sources.list"
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

echo "[+] Hostname: kali"
# Set hostname
echo "kali" > kali-$architecture/etc/hostname

echo "[+] Hosts file"
# So X doesn't complain, we add kali to hosts
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       kali    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF
chmod 644 kali-$architecture/etc/hosts

#cat << EOF > kali-$architecture/etc/network/interfaces
#auto lo
#iface lo inet loopback

# This is to allow setup for Pi zero on address 1.0.0.1 which is compatible with poisontap
#auto usb0
#allow-hotplus usb0
#iface usb0 inet static
#  address 1.0.0.1
#  netmask 0.0.0.0
#EOF
#chmod 644 kali-$architecture/etc/network/interfaces

cat << EOF > kali-$architecture/etc/resolv.conf
nameserver 8.8.8.8
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service
#
[Unit]
Description=Regenerate SSH host keys

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c "if [ -e /dev/hwrng ]; then dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096; fi"
ExecStart=/usr/bin/ssh-keygen -A
ExecStartPost=/bin/rm /lib/systemd/system/regenerate_ssh_host_keys.service ; /usr/sbin/update-rc.d regenerate_ssh_host_keys remove

[Install]
WantedBy=multi-user.target
EOF
chmod 755 kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service

# Copy Tweaks to tmp folder
cp $TOPDIR/misc/xfce4-setup.sh kali-$architecture/tmp/xfce4-setup.sh
cp $TOPDIR/misc/bashtweaks.sh kali-$architecture/tmp/bashtweaks.sh

echo "[+] Begin THIRD STAGE"
cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local /lib/udev/rules.d/75-persistent-net-generator.rules
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get --yes --force-yes install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools curl
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
wget https://gist.githubusercontent.com/sturadnidge/5695237/raw/444338d0389da39f5df615ff47ceb12d41be7fdb/75-persistent-net-generator.rules -O /lib/udev/rules.d/75-persistent-net-generator.rules
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules

echo "[+] Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --force-yes install $packages &&
apt-get --yes --force-yes dist-upgrade
apt-get --yes --force-yes autoremove

echo "[+] Removing generated ssh keys"
rm -f /etc/ssh/ssh_host_*_key*

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
echo "[+] Making root great again"
sed -i -e 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Fix startup time from 5 minutes to 15 secs on raise interface wlan0
sed -i 's/^TimeoutStartSec=5min/TimeoutStartSec=15/g' "/lib/systemd/system/networking.service" 

update-rc.d ssh enable

############## Extra g0tmi1k apps ###############

# Fun MOTD
echo "Connect through serial with on host computer: sudo screen /dev/ttyACM0 115200" | /usr/games/cowsay > /etc/motd

# SSH Allow authorized keys
sed -i 's/^#AuthorizedKeysFile /AuthorizedKeysFile /g' "/etc/ssh/sshd_config"  # Allow for key based login

############################################################
# Depends for rasp-config
apt-get install -y libnewt0.52 whiptail parted triggerhappy lua5.1 alsa-utils
apt-get install -fy

# Add Login Screen Tweaks
# Add virtual keyboard to login screen
echo "[greeter]" > /etc/lightdm/lightdm-gtk-greeter.conf
echo "show-indicators=~language;~a11y;~session;~power" >> /etc/lightdm/lightdm-gtk-greeter.conf
echo "keyboard=florence --focus" >> /etc/lightdm/lightdm-gtk-greeter.conf
# Background image and change logo
echo "background=/usr/share/images/desktop-base/kali-lockscreen_1280x1024.png" >> /etc/lightdm/lightdm-gtk-greeter.conf
echo "default-user-image=#kali-k" >> /etc/lightdm/lightdm-gtk-greeter.conf

################################
# Install poisontap and hackpi #
################################
adduser pi
echo 'pi:raspberry' | chpasswd
mkdir -p /home/pi
cd /home/pi
git clone https://github.com/wismna/HackPi
chown -R pi HackPi
cd HackPi
cp isc-dhcp-server /etc/default/isc-dhcp-server
cp dhcpd.conf /etc/dhcp/dhcpd.conf
cp interfaces /etc/network/interfaces
chmod +x *.sh
cd ..
git clone https://github.com/samyk/poisontap.git
chown -R pi poisontap
cd poisontap
cp dhcpd.conf /etc/dhcp
cd ..
git clone https://github.com/lgandx/Responder
cd ..
echo "[+] Install nodejs"
mkdir -p /tmp/node
cd /tmp/node
wget https://raw.githubusercontent.com/sdesalas/node-pi-zero/master/install-node-v6.4.0.sh
./install-node-v6.4.0.sh
ln -s /lib/ld-linux.so.3 /lib/ld-linux-armhf.so.3
cd /
rm -rf /tmp/node

# Raspi-config install
echo "[+] Install raspi-config"
cd /tmp
wget http://archive.raspberrypi.org/debian/pool/main/r/raspi-config/raspi-config_20161207_all.deb
dpkg -i raspi-config_*

# XFCE stuff (both users?)
echo "[+] Running XFCE setup"
chmod +x /tmp/xfce4-setup.sh
/tmp/xfce4-setup.sh


echo "[+] Running bash tweaks"
chmod +x /tmp/bashtweaks.sh
/tmp/bashtweaks.sh

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

# Execute Third-Stage
chmod +x kali-$architecture/third-stage
LANG=C chroot kali-$architecture /third-stage

####### END THIRD STAGE - CLEANUP ################

cat << EOF > kali-$architecture/cleanup
#!/bin/bash
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -rf /tmp/*.deb
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*
EOF

chmod +x kali-$architecture/cleanup
LANG=C chroot kali-$architecture /cleanup

# Raspbian Configs worth adding

#cat << EOF > kali-$architecture/etc/wpa_supplicant/wpa_supplicant.conf
#country=GB
#ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
#update_config=1
#EOF
#chmod 600 kali-$architecture/etc/wpa_supplicant/wpa_supplicant.conf

cat << EOF > kali-$architecture/etc/apt/apt.conf.d/50raspi
# never use pdiffs. Current implementation is very slow on low-powered devices
Acquire::PDiffs "0";
# download up to 5 pdiffs:
#Acquire::PDiffs::FileLimit "5";
EOF
chmod 644 kali-$architecture/etc/apt/apt.conf.d/50raspi

cat << EOF > kali-$architecture/etc/modprobe.d/ipv6.conf
# Don't load ipv6 by default
alias net-pf-10 off
#alias ipv6 off
EOF
chmod 644 kali-$architecture/etc/modprobe.d/ipv6.conf

umount -l kali-$architecture/dev/pts
umount -l kali-$architecture/dev/
umount -l kali-$architecture/proc
}

function ask() {
    # http://djm.me/ask
    while true; do

        if [ "${2:-}" = "Y" ]; then
            prompt="Y/n"
            default=Y
        elif [ "${2:-}" = "N" ]; then
            prompt="y/N"
            default=N
        else
            prompt="y/n"
            default=
        fi

        # Ask the question
        read -p "$1 [$prompt] " REPLY

        # Default?
        if [ -z "$REPLY" ]; then
            REPLY=$default
        fi

        # Check if the reply is valid
        case "$REPLY" in
            Y*|y*) return 0 ;;
            N*|n*) return 1 ;;
        esac
    done
}

function build_image(){

echo "*********************************************"
echo "$(tput setaf 2)
   .~~.   .~~.
  '. \ ' ' / .'$(tput setaf 1)
   .~ .~~~..~.
  : .~.'~'.~. :
 ~ (   ) (   ) ~
( : '~'.~.'~' : )
 ~ .~ (   ) ~. ~
  (  : '~' :  ) $(tput sgr0)Kali PI0 Image Generator$(tput setaf 1)
   '~ .~~~. ~'
       '~'
$(tput sgr0)"
echo "*********************************************"
mkdir -p ${basedir}

size=7000 # Size of image in megabytes

# Create the disk (img file) and partition it
echo "[+] Creating image file for Raspberry Pi0"
dd if=/dev/zero of=${basedir}/kali-$VERSION-rpi0.img bs=1M count=$size
parted ${basedir}/kali-$VERSION-rpi0.img --script -- mklabel msdos
parted ${basedir}/kali-$VERSION-rpi0.img --script -- mkpart primary fat32 0 64
parted ${basedir}/kali-$VERSION-rpi0.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
# http://matthewkwilliams.com/index.php/2015/10/09/mounting-partitions-from-image-files-on-linux/
loopdevice=`losetup -f --show ${basedir}/kali-$VERSION-rpi0.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
echo "${bootp} ${rootp}"
echo "[+] BOOTP filesystem mkfs.vfat"
mkfs.vfat $bootp
echo "[+] ROOT filesystem mkfs.ext4"
mkfs.ext4 $rootp

# Create the dirs for the partitions bootp & root and mount them
echo "[+] Creating ${basedir}/bootp ${basedir}/root folders and mounting"
mkdir -p ${basedir}/bootp ${basedir}/root
mount -t vfat $bootp ${basedir}/bootp
mount -t ext4 $rootp ${basedir}/root

# Copy kali to /root folder
echo "[+] Rsyncing rootfs ${DIRECTORY}/ into root folder for image: ${basedir}/root/"
rsync -HPavz -q ${DIRECTORY}/ ${basedir}/root/

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt100" >> ${basedir}/root/etc/inittab

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main contrib non-free
#deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.

# RPI Firmware (copy to /boot)
echo "[+] Copying Raspberry Pi Firmware to /boot"
git clone --depth 1 https://github.com/raspberrypi/firmware.git rpi-firmware
cp -rf rpi-firmware/boot/* ${basedir}/bootp/
rm -rf ${basedir}/root/lib/firmware  # Remove /lib/firmware to copy linux firmware
rm -rf rpi-firmware

# Linux Firmware (copy to /lib)
echo "[+] Copying Linux Firmware to /lib"
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git

# Make kernel
echo "*********************************************"
echo "
$(tput setaf 2)
------\\
_____  \\
     \  \\
     |  |
     |  |
     |  |
     |  |
     |  |
  ___|  |_______
 /--------------\\
 |              |
 |           .--|
 |  KERNEL   .##|
 |  BAKING   .##|
 |            --|  $(tput sgr0)Time to bake the kernel!$(tput setaf 1)
 |              |
 \______________/
  #            #
  $(tput sgr0)"
echo "*********************************************"
echo ""
echo "[+] Downloading kernel"
git submodule update --init --recursive
cd ${TOPDIR}/tools
git pull
# Kernel and firmware
git clone --depth 1 https://github.com/nethunteros/re4son-raspberrypi-linux.git -b rpi-4.4.y-re4son ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
export ARCH=arm
export KERNEL=kernel
export CROSS_COMPILE=${TOPDIR}/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-

# Make kernel with re4sons defconfig
echo "[+] Building kernel and modules"
#make ARCH=arm bcmrpi_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- re4son_pi1_defconfig
make -j $(grep -c processor /proc/cpuinfo) zImage modules dtbs

echo "[+] Copying kernel"
perl scripts/mkknlimg --dtok arch/arm/boot/zImage ${basedir}/bootp/kernel.img
cp arch/arm/boot/dts/*.dtb ${basedir}/bootp/
cp arch/arm/boot/dts/overlays/*.dtb* ${basedir}/bootp/overlays/
cp arch/arm/boot/dts/overlays/README ${basedir}/bootp/overlays/

echo "[+] Creating and copying modules"
make ARCH=arm firmware_install INSTALL_MOD_PATH=${basedir}/root

echo "[+] Making kernel headers"
make ARCH=arm headers_install INSTALL_HDR_PATH=${basedir}/root/usr

# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
cat << EOF > ${basedir}/root/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc /proc proc nodev,noexec,nosuid 0  0
/dev/mmcblk0p2  / ext4 errors=remount-ro 0 1
# Change this if you add a swap partition or file
#/var/swapfile none swap sw 0 0
/dev/mmcblk0p1 /boot vfat noauto 0 0
EOF

# Unmount partitions
umount -l $bootp
umount -l $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}/kernel
rm -rf ${basedir}/bootp
rm -rf ${basedir}/root
rm -rf ${basedir}/boot
rm -rf ${basedir}/patches

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}/bootp
rm -rf ${basedir}/root

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
OUTPUTFILE="${basedir}/kali-$VERSION-rpi0.img"

if [ -f "${OUTPUTFILE}" ]; then

    dir=/tmp/rpi
    test "umount" = "${OUTPUTFILE}" && sudo umount $dir/boot && sudo umount $dir
    image="${OUTPUTFILE}"
    test -r "$image"

    o_boot=`sudo sfdisk -l $image | grep FAT32 | awk '{ print $2 }'`
    o_linux=`sudo sfdisk -l $image | grep Linux | awk '{ print $2 }'`

    echo "Mounting img o_linux: $o_linux and o_boot: $o_boot"
    test -d $dir || mkdir -p $dir
    sudo mount -o offset=`expr $o_linux \* 512`,loop $image $dir
    sudo mount -o offset=`expr $o_boot  \* 512`,loop $image $dir/boot
    sudo mount -t proc proc $dir/proc
    sudo mount -o bind /dev/ $dir/dev/
    sudo mount -o bind /dev/pts $dir/dev/pts

    cp /usr/bin/qemu-arm-static $dir/usr/bin/
    chmod +755 $dir/usr/bin/qemu-arm-static

cat << EOF > $dir/tmp/fixkernel.sh
#!/bin/bash
echo "[+] Fixing kernel symlink"
# Symlink is broken since we build outside of device (will link to host system)
rm -rf /lib/modules/4.4.45-v7+/build
ln -s /usr/lib/arm-linux-gnueabihf/libisl.so /usr/lib/arm-linux-gnueabihf/libisl.so.10
ln -s /usr/src/kernel /lib/modules/4.4.45-v7+/build
# make scripts doesn't work if we cross crompile
cd /usr/src/kernel
make ARCH=arm scripts
EOF

    echo "[+] Enable sshd at startup"
    chroot $dir /bin/bash -c "update-rc.d ssh enable"

    echo "[+] Symlink to build"
    chroot $dir /bin/bash -c "chmod +x /tmp/fixkernel.sh"

    rm -f $dir/tmp/*

    # Create cmdline.txt file
    echo "[+] Creating /boot/cmdline.txt"
cat << EOF > $dir/boot/cmdline.txt
dwc_otg.lpm_enable=0 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 elevator=deadline root=/dev/mmcblk0p2 rootfstype=ext4 rootwait net.ifnames=0
EOF

    # Create config.txt file
    echo "[+] Creating /boot/config.txt"
cat << EOF > $dir/boot/config.txt
dtoverlay=dwc2
EOF

    # RC LOCAL
cat << EOF > $dir/etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

# Print the IP address
_IP=$(hostname -I) || true
if [ "$_IP" ]; then
  printf "My IP address is %s\n" "$_IP"
fi

# Parse USB requests in dmesg
/bin/bash /home/pi/HackPi/fingerprint.sh | tee /home/pi/os.txt

# Stop the dummy gadget and start the real one
modprobe -r g_ether
modprobe libcomposite

# libcomposite configuration
/bin/sh /home/pi/HackPi/gadget.sh | tee /home/pi/HackPi/gadget.log

# Start bridge interface
ifup br0
ifconfig br0 up

# Clear leases
#rm -f /var/lib/dhcp/dhcpd.leases
#touch /var/lib/dhcp/dhcpd.leases

# Start the DHCP server
/sbin/route add -net 0.0.0.0/0 br0
/etc/init.d/isc-dhcp-server start
# Set some other paramaters
/sbin/sysctl -w net.ipv4.ip_forward=1
/sbin/iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-port 1337
# Start some servers
#/usr/bin/screen -dmS dnsspoof /usr/sbin/dnsspoof -i br0 port 53
#/usr/bin/screen -dmS node /usr/bin/nodejs /home/pi/poisontap/pi_poisontap.js 

# Enable Serial
systemctl enable getty@ttyGS0.service

# Start Responder
#/usr/bin/screen -dmS responder bash -c 'cd /home/pi/Responder/; python Responder.py -I br0 -f -w -r -d -F'

exit 0
EOF
chmod +x $dir/etc/rc.local

    # Ethernet module
    echo -e "dwc2\ng_ether" >> $dir/etc/modules

    # systemd doesn't seem to be generating the fstab properly for some people, so
    # let's create one.
    echo "[+] Creating /etc/fstab"
cat << EOF > $dir/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc /proc proc nodev,noexec,nosuid 0  0
/dev/mmcblk0p2  / ext4 errors=remount-ro 0 1
# Change this if you add a swap partition or file
#/dev/SWAP none swap sw 0 0
/dev/mmcblk0p1 /boot vfat noauto 0 0
EOF

    # Enable regenerate ssh host keys at first boot
    chroot $dir /bin/bash -c "systemctl enable regenerate_ssh_host_keys"

    echo "[+] Unmounting"
    sleep 10
    sudo umount $dir/boot
    sudo umount -l $dir/proc
    sudo umount -l $dir/dev/
    sudo umount -l $dir/dev/pts
    sudo umount $dir
    rm -rf $dir

    # Generate sha1sum
    cd ${basedir}
    echo "Generating sha1sum for ${OUTPUTFILE}"
    sha1sum ${OUTPUTFILE} > ${OUTPUTFILE}.sha1sum

    # Compress output if true
    if [ "$COMPRESS" = true ] ; then
       echo "Compressing ${OUTPUTFILE}"
       xz -z ${OUTPUTFILE}
       echo "Generating sha1sum for kali-$VERSION-rpi0.img.xz"
       sha1sum ${OUTPUTFILE}.xz > ${OUTPUTFILE}.xz.sha1sum
    fi

    echo "[!] Finished!"
else
    echo "${OUTPUTFILE} NOT FOUND!!! SOMETHING WENT WRONG!?"
fi
}

if [ ! -d "$DIRECTORY" ]; then
    if ask "[?] Missing chroot. Build?"; then
        build_chroot
        build_image
    else
        exit
    fi
else
    if ask "[?] Previous chroot found.  Build new one?"; then
        build_chroot
        build_image
    else
        echo "Skipping chroot build"
        build_image
    fi
fi
