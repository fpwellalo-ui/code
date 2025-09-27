#!/bin/sh
apt update
apt install -y screen zmap gcc g++
gcc src/*.c -o android -s -Os -lpthread
screen -S scan -dm sh scan.sh
