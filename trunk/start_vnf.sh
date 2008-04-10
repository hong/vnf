#!/bin/sh
export PATH=/sbin:/bin

insmod ./vnf.ko $*
ifconfig vnf0 up
