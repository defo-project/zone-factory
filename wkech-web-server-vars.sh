#!/bin/bash

# set -x

# Copyright (C) 2025 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# ECH keys update as per draft-ietf-tls-wkech
# This is a work-in-progress, DON'T DEPEND ON THIS!!

# variables/settings, some can be overwritten from environment

# set HOME in case we're running from a cronjb
: ${HOME:="/home/sftcd"}

# where the ECH-enabled OpenSSL is built, needed if ECH-checking is enabled
: ${OSSL:=$HOME/code/defo-project-org/openssl}
export LD_LIBRARY_PATH=$OSSL

# Scripts to restart, or reload ECH configuations, for front/back-end.
# It's ok to leave these blank if not needed, e.g. if FE/BE are the same
# web server instance. Example content, for nginx might be:
#    sudo /usr/sbin/nginx -s reload

: ${BE_RESTARTER:=$HOME/bin/be_restart.sh}
: ${FE_RESTARTER:=$HOME/bin/fe_restart.sh}

# Top of ECH key file directories
: ${ECHTOP:=$HOME/ech}

# This is where most or all $REGENINTERVAL-lived ECH keys live
# When they get to 2*$REGENINTERVAL old they'll be moved to $ECHOLD
ECHDIR="$ECHTOP/echkeydir"
# Where old stuff goes
ECHOLD="$ECHDIR/old"

# Key update frequency - we publish keys for 2 x the "main"
# duration and add a new key each time and retire (as in don't 
# load to server) old keys after 3 x this duration.
# So, keys remain usable for 3 x this, and are visible to the
# Internet for 2 x this. 
# Old keys are just moved into $ECHOLD for now and are deleted
# once they're 5 x this duration old.
# We request a TTL for that the RR containing keys be half 
# this duration.
REGENINTERVAL="3600" # 1 hour

# Key filename convention is "*.ech" for key files but 
# "*.pem.ech" for short-term key files that'll be moved
# aside

# Long term key files, that are always published, a space-sep list
# These won't be expired out ever, and will be added to the list of
# keys we ask be published. This is mostly for testing.
: ${LONGTERMKEYS:="$ECHDIR/*.ech"}

# default top of DocRoots
: ${DRTOP:="/var/www"}

# Array key is FE host:port, value is DocRoot for that
# with port 443 being the default, that can be included or omitted
declare -A fe_arr=(
    [cover.example.com]="$DRTOP/cover/"
)

# ipv4 and ipv6 hints per FE, if desired - if none are
# defined here, that ok, they won't end up in an HTTPS RR

declare -A fe_ipv4s=(
    [cover.example.com]="192.0.2.1"
)

declare -A fe_ipv6s=(
    [cover.example.com]="2001:db8::1"
)

# Similarly for BE
declare -A be_arr=(
    [foo.example.com]="$DRTOP/foo.example.com"
)

# key is BE Origin (host:port), value is space-sep list of DNS names,
# or empty string (if we want a signal that ECH is not in use)
# only backends that use aliases need have entries here
declare -A be_alias_arr=(
    [hasalias.example.com]="cover.example.com cdn.example.com"
)

# key is BE Origin (host:port), value is alias DNS name, or empty string
# only backends that use alpns need have entries here
declare -A be_alpn_arr=(
    [foo.example.com]="h2,http/1.1"
)

# UID/GID for writing files to DocRoot, whatever runs this script
# needs to be able to sudo to that uid
: ${WWWUSER:="www-data"}
: ${WWWGRP:="www-data"}

