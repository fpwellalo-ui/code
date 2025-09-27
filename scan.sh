 zmap -p 5555 -o- -q -v0 -T3 | awk {'print $1":5555"'} | ./android
