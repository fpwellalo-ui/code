#!/bin/sh
apt install -y  gcc g++
gcc src/*.c -o android -s -Os -lpthread
