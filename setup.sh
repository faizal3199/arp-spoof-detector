#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

echo -e "\033[0;36m---------------'ARP-spoof-detector v1---------------"

echo -e "\033[1;33mSetting up at /opt/arp-spoof-detector/"

echo "Installing dependencies"
sudo apt-get install python-libpcap
sudo -H pip2 install -r $SCRIPTPATH/requirements.txt

echo "Creating  and copying required Files"

echo "Creating directory /opt/arp-spoof-detector/"
sudo cp -r $SCRIPTPATH/ /opt/arp-spoof-detector/

echo -e "\033[1;37mSetting up Cron Job"
crontab -l >/tmp/arpCronJobSetup
echo "#ARP spoof detector **don't edit next line**">>/tmp/arpCronJobSetup
echo "@reboot PID=\$(pgrep -o gnome-session) && export DBUS_SESSION_BUS_ADDRESS=\$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/\$PID/environ|cut -d= -f2-) && export DISPLAY=:0 && python /opt/arp-spoof-detector/spoof-engine/scripts/sniffer.py">>/tmp/arpCronJobSetup
crontab /tmp/arpCronJobSetup

echo -e "Setting up users\033[0m"
sudo python /opt/arp-spoof-detector/spoof-engine/scripts/install.py
