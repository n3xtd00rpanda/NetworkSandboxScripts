#!bin/bash
sudo apt-get update && sudo apt-get upgrade -y
# Create a Cuckoo user
sudo adduser cuckoo
sudo adduser cuckoo sudo
# Now we will install the prerequisites for Cuckoo.
sudo apt-get install curl
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo apt-get install python
sudo python get-pip.py
sudo apt-get install -y python-dev libffi-dev libssl-dev libfuzzy-dev libtool flex autoconf libjansson-dev git
sudo apt-get install -y python-setuptools
sudo apt-get install -y libjpeg-dev zlib1g-dev swig
sudo apt-get install -y mongodb
sudo apt-get install -y postgresql libpq-dev
# Now we will download and install all the plugins needed for cuckoo to work.
cd Downloads/
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
sudo python setup.py build
sudo python setup.py install
cd ..
sudo -H pip install distorm3==3.4.4
sudo -H pip install yara-python==3.6.3
sudo apt-get install -y ssdeep
ssdeep -V
sudo -H pip install pydeep
pip show pydeep
sudo -H pip install openpyxl
sudo -H pip install ujson
sudo -H pip install jupyter
# Now we will install TCPDump to enable packet capture analysis
sudo apt-get install tcpdump
sudo apt-get install libcap2-bin
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
# We need to install and disable apparmor due to its stealthy protection
sudo apt-get install -y apparmor-utils
sudo aa-disable /usr/sbin/tcpdump