#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[0;31mPlease run as root\033[0m"
  exit 126
fi

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

echo -e "\033[95m---------------ARP-spoof-detector v1---------------\033[0m\n"

echo -e "\033[1;94mSetting up at /opt/arp-spoof-detector/\033[0m\n"

echo -e "\033[1;33mInstalling dependencies\033[0m"
sudo apt-get install python-libpcap
sudo -H pip2 install -r $SCRIPTPATH/requirements.txt

echo -e "\n\033[33mCreating and copying required Files\033[0m"

echo -e "\033[33mCreating directory /opt/arp-spoof-detector/\033[0m\n"
sudo rm -rf /opt/arp-spoof-detector/
sudo cp -r $SCRIPTPATH/ /opt/arp-spoof-detector/

# echo -e "\033[1;94mSetting up Cron Job at every restart\033[0m\n"
# crontab -l >/tmp/arpCronJobSetup
# echo "#ARP spoof detector **don't edit next line**">>/tmp/arpCronJobSetup
# echo "@reboot PID=\$(pgrep -o gnome-session) && export DBUS_SESSION_BUS_ADDRESS=\$(grep -z DBUS_SESSION_BUS_ADDRESS /proc/\$PID/environ|cut -d= -f2-) && export DISPLAY=:0 && python /opt/arp-spoof-detector/spoof-engine/scripts/sniffer.py">>/tmp/arpCronJobSetup
# crontab /tmp/arpCronJobSetup

echo -e "\033[33mSetting up users\033[0m"
sudo python /opt/arp-spoof-detector/spoof-engine/scripts/install.py

if [ $? -eq 0 ]; then
  echo -e "\033[33mStarting service\033[0m"
  sudo python /opt/arp-spoof-detector/spoof-engine/scripts/sniffer.py
fi
