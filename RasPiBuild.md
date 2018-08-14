
yum install flex

BASE=/home/ec2-user/environment/build

cd $BASE

git clone git://github.com/raspberrypi/tools.git
export PATH=$PATH:$BASE/tools/arm-bcm2708/arm-linux-gnueabihf/bin

export PCAPV=1.8.1
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar xvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
env CC=arm-linux-gnueabihf-gcc ./configure --host=arm-linux --with-pcap=linux
env CC=arm-linux-gnueabihf-gcc make

cd ~/environment

env CC=arm-linux-gnueabihf-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_LDFLAGS="-L$BASE/libpcap-$PCAPV" CGO_CFLAGS="-I$BASE/libpcap-$PCAPV" go build pmux.go

Emits `pmux` binary, which should be ready to go


./pmux <interface> <password>

Listens on 2222 and expects <password>