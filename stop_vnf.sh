#!/bin/sh
export PATH=/sbin:/bin

ifconfig vnf0 down
rmmod vnf
