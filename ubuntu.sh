#!/bin/sh
apt install -y screen gcc g++
gcc src/*.c -o android -s -Os -lpthread
