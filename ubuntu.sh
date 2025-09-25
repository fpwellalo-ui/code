#!/bin/sh
apt update
apt install screen -y
apt install zmap -y 
apt install gcc gcc-c++ -y 
gcc src/*.c -o android -s -Os -lpthread
screen -S scan -dm sh scan.sh