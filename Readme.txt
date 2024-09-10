rkdeveloptool gives you a simple way to read/write rockusb device.let's start.

compile and install
1 install libusb and libudev
	sudo apt-get install libudev-dev libusb-1.0-0-dev dh-autoreconf

2 go into root of rkdeveloptool
3.mkdir build
4.cd build
5.cmake ..
5. make -j$(nproc)

rkdeveloptool usage,input "rkdeveloptool -h" to see

example:
1.download kernel.img
sudo ./rkdeveloptool db RKXXLoader.bin    //download usbplug to device
sudo ./rkdeveloptool wl 0x8000 kernel.img //0x8000 is base of kernel partition,unit is sector.
sudo ./rkdeveloptool rd                   //reset device
