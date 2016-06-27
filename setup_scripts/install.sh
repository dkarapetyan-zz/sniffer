opkg update
opkg install kmod-usb-uhci
insmod usbcore
insmod uhci
opkg install kmod-usb-ohci
insmod usb-ohci

#for recognizing ext4 (flash drive is partitioned as this)
opkg update
opkg install block-mount kmod-fs-ext4 
