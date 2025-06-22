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

# ECH key management as per draft-ietf-tls-wkech
# This is a work-in-progress, DON'T DEPEND ON THIS!!

# This script handles ECH key updating for an ECH client-facing server or 
# front-end (in ECH split-mode), back-end (e.g. web server).
# The zone-factory side of this is implemented in wkech-zf.py

# This makes use of our ECH-enabled OpenSSL forl. A good place for guidance
# no how to get that working is: https://github.com/defo-project 

# Paths that  can be overidden
: "${OSSL:=$HOME/code/defo-project-org/openssl}"
: "${ECHDT:=$HOME/code/defo-project-org/ech-dev-utils}"

# File that sets specific variables/arrays of front-end and back-end
# details.
: "${VARSFILE:=wkech-web-server-vars.sh}"

# variables/settings, some can be overwritten from environment all can be
# over-ridden via a local wkech-web-server-vars.sh file to include
# see explanations in wkech-web-server-vars.sh for details
if [ ! -f "$VARSFILE" ]
then
    echo "Can't read $VARSFILE - exiting"
    exit 99
fi
# shellcheck source=./wkech-web-server-vars.sh
. "${VARSFILE}"

# Fixed by draft
WESTR="origin-svcb"

# more paths, possibly partly overidden
export LD_LIBRARY_PATH=$OSSL
# role strings
FESTR="fe"
BESTR="be"

# default roles, works for shared-mode client-facing and backed instance
ROLES="$FESTR,$BESTR"

# if our ROLE is only BE then we'll use curl to try grab a .well-knonw
# from the configured FE using curl, so we need a timeout
CURLTIMEOUT=10

# whether to only make one public key available for publication
# from front-end .well-known
JUSTONE="no"

# yeah, 443 is the winner:-)
DEFPORT=443

function whenisitagain()
{
    /bin/date -u +%Y%m%d-%H%M%S
}

function fileage()
{
    echo $(($(date +%s) - $(date +%s -r "$1")))
}

function hostport2host()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo "$host"
}

function hostport2port()
{
    case $1 in
      *:*) host=${1%:*} port=${1##*:};;
        *) host=$1      port=$DEFPORT;;
    esac
    echo "$port"
}

function makecheckdir()
{
    user="$1"
    group="$2"
    dir="$3"

	if [ ! -d "$dir" ]
	then
	    sudo -u "$user" mkdir -p "$dir"
	fi
	if [ ! -d "$dir" ]
	then
	    echo "$dir missing - exiting"
	    exit 114
	fi
    sudo chown "$user:$group" "$dir"
}

# produce a JSON array of strings, given an input CSV
# we do not support any escaping
function csv2jarr()
{
    qcsv=${1//,/\",\"}
    output="[\"$qcsv\"]"
    echo "$output"
}

# Make the JSON structure to be published at a wkech .well-known 
function makesvcjson()
{
    file=$1
    dur=$2
    priostr=$3
    ipv4str=$4
    echstr=$5
    ipv6str=$6
    alpnstr=$7
    if [[ "$ipv4str" == ""  && "$echstr" == "" \
        && "$ipv6str" == "" && "$alpnstr" == "" ]]
    then
        cat <<EOF >"$file"
{
 "regeninterval" : $dur,
 "endpoints": []
}
EOF
        return
    fi
    NL=$',\n      '
    c2=""
    if [ "$alpnstr" != "" ]
    then
        if [ "$ipv6str" != "" ] || [ "$echstr" != "" ] || [ "$ipv4str" != "" ]
        then
            c2=$NL
        fi
    fi
    c1=""
    if [ "$ipv6str" != "" ]
    then
        if [ "$echstr" != "" ] || [ "$ipv4str" != "" ]
        then
            c1=$NL
        fi
    fi
    c0=""
    if [ "$echstr" != "" ] && [ "$ipv4str" != "" ]
    then
        c0=$NL
    fi
    lpriostr=""
    if [ "$priostr" != "0" ]
    then
        lpriostr='"priority" : '$priostr$',\n    '
    fi
    cat <<EOF >"$file"
{
 "regeninterval" : $dur,
 "endpoints" : [ {
    $lpriostr"params" : {
      $ipv4str$c0$echstr$c1$ipv6str$c2$alpnstr
    }
 }]
}
EOF
    return
}

function makealiasjson()
{
    file=$1
    dur=$2
    aliasstr=$3

    if [ "$aliasstr" == "" ] 
    then
        cat <<EOF >"$file"
{
 "regeninterval" : $dur,
 "endpoints": []
}
EOF
        return
    fi
    cat <<EOF >"$file"
{
 "regeninterval" : $dur,
 "endpoints" : [{
    "alias" : "$aliasstr"
  }]
}
EOF
    return
}

function usage()
{
    echo "$0 [-h] [-r roles] [-d duration] - generate new ECHKeys as needed."
    echo "  -d specifies key update frequency in seconds (for testing really)"
    echo "  -h means print this"
    echo "  -r roles can be \"$FESTR\" or \"$FESTR,$BESTR\" or \"$BESTR\" " \
         "(default is \"$ROLES\")"
    echo "  -1 only make 1 public key available .well-known"

	echo ""
	echo "The following should work:"
	echo "    $0 "
    exit 1
}

echo "=========================================="
NOW=$(whenisitagain)
echo "Running $0 at $NOW"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o 1hi:r: -l one,help,intervaal:,roles: -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 2
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -1|--one) JUSTONE="yes";;
        -h|--help) usage;;
        -i|--interval) REGENINTERVAL=$2; shift;;
        -r|--roles) ROLES=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 3;;
        (*)  break;;
    esac
    shift
done

# variables that can be influenced by command line options

# Various multiples/fractions of REGENINTERVAL
dur=$REGENINTERVAL
durt2=$((REGENINTERVAL*2))
durt3=$((REGENINTERVAL*3 + 60)) # allow a bit of leeway
durt5=$((REGENINTERVAL*5))

# set this if we did something that needs e.g. a server restart/reload
restartactiontaken="false"

# sanity checks

case $ROLES in
    "$FESTR")
        ;;
    "$FESTR,$BESTR")
        ;;
    "$BESTR")
        ;;
    *)
        echo "Bad role(s): $ROLES - exiting"
        exit 4
esac

# checks for front-end role
if [[ $ROLES == *"$FESTR"* ]]
then

    # check that the that OpenSSL build is built
    if [ ! -f "$OSSL/apps/openssl" ]
    then
        echo "OpenSSL not built - exiting"
        exit 5
    fi
    # check for another script we need
    if [ ! -f "$ECHDT/scripts/mergepems.sh" ]
    then
        echo "$ECHDT/scripts/mergepems.sh not seen - exiting"
        exit 6
    fi
    # check that our OpenSSL build supports ECH
    "$OSSL/apps/openssl" ech -help >/dev/null 2>&1
    eres=$?
    if [[ "$eres" != "0" ]]
    then
        echo "OpenSSL not built with ECH - exiting"
        exit 8
    fi
    # check/make various directories
    if [ ! -d "$ECHTOP" ]
    then
        echo "$ECHTOP ECH key dir missing - exiting"
        exit 7
    fi
    makecheckdir "$USER" "$USER" "$ECHDIR"
    makecheckdir "$USER" "$USER" "$ECHOLD"
    # check/make docroot and .well-known if needed
    for feor in "${!fe_arr[@]}"
    do
        # echo "FE origin: $feor, DocRoot: ${fe_arr[${feor}]}"
        fedr=${fe_arr[${feor}]}
        fewkechdir=$fedr/.well-known/
        makecheckdir "$WWWUSER" "$WWWGRP" "$fewkechdir"
    done
fi

if [[ $ROLES == *"$BESTR"* ]]
then
    # check docroots and if we can sudo to www-user
    for beor in "${!be_arr[@]}"
    do
        bedr=${be_arr[${beor}]}
        makecheckdir "$WWWUSER" "$WWWGRP" "$bedr/.well-known"
        if [ ! -f "$bedr/.well-known/$WESTR" ]
        then
            sudo -u "$WWWUSER" touch "$bedr/.well-known/$WESTR"
        fi
        if [ ! -f "$bedr/.well-known/$WESTR" ]
        then
            echo "Failed sudo'ing to $WWWUSER to make $bedr/.well-known/$WESTR - exiting"
            exit 15
        fi
    done
    wns=$(which jq)
    if [[ "$wns" == "" ]]
    then
        echo "Can't see jq - exiting"
        exit 11
    fi
fi

if [[ $ROLES == *"$FESTR"* ]]
then

    for feor in "${!fe_arr[@]}"
    do
        echo "Checking if new ECHKeys needed for $feor"
        actiontaken="false"

        feport=$(hostport2port "$feor")
        fehost=$(hostport2host "$feor")
        fedr=${fe_arr[${feor}]}
        fewkechfile=$fedr/.well-known/$WESTR

        # Plan:

        # - check creation date of existing ECHConfig key pair files
        # - if all ages < REGENINTERVAL then we're done and exit
        # - Otherwise:
        #   - generate new instance of ECHKeys (same for backends)
        #   - retire any keys >3*REGENINTERVAL old
        #   - delete any keys >5*REGENINTERVAL old
        #   - push updated JSON (for all keys) to DocRoot dest

        newest=$durt5
        newf=""
        oldest=0
        oldf=""

        echo "Prime key lifetime: $REGENINTERVAL seconds"
        echo "New key generated when latest is $dur old"
        if [[ "$JUSTONE" == "yes" ]]
        then
            echo "Only latest key (age <$dur) will be made available"
        else
            echo "Keys will be published while younger than $durt2"
        fi
        echo "Old keys moved aside (not loaded) when older than $durt3"
        echo "Keys wll be deleted when older than $durt5"

        makecheckdir "$USER" "$USER" "$ECHDIR/$fehost.$feport"
        files2check="$ECHDIR/$fehost.$feport/*.pem.ech"
        for file in $files2check
        do
            if [ ! -f "$file" ]
            then
                continue
            fi
            fage=$(fileage "$file")
            echo "$file is $fage old"
            if ((fage < newest))
            then
                newest=$fage
                newf=$file
            fi
            if ((fage > oldest))
            then
                oldest=$fage
                oldf=$file
            fi
            if ((fage > durt3))
            then
                echo "$file is old, (age==$fage >= $durt3)... moving to $ECHOLD"
                mv "$file" "$ECHOLD"
                actiontaken="true"
                restartactiontaken="true"
            fi
        done
        echo "Oldest PEM file is $oldf (age: $oldest)"
        echo "Newest PEM file is $newf (age: $newest)"

        # delete files older than 5*REGENINTERVAL
        oldies="$ECHOLD/*"
        for file in $oldies
        do
            if [ -f "$file" ]
            then
                fage=$(fileage "$file")
                if ((fage >= durt5))
                then
                    rm -f "$file"
                fi
            fi
        done

        keyn="ech$(date +%s)"
        if ((newest >= (dur-1)))
        then
            echo "Time for a new key pair (newest as old or older than $dur)"
            "$OSSL/apps/openssl" ech -public_name "$fehost" \
                -out "$ECHDIR/$fehost.$feport/$keyn.pem.ech"
            res=$?
            if [[ "$res" != "0" ]]
            then
                echo "Error generating $ECHDIR/$fehost.$feport/$keyn.pem.ech"
                exit 15
            fi
            actiontaken="true"
            restartactiontaken="true"
            newf="$ECHDIR/$fehost.$feport/$keyn.pem.ech"
        fi

        if [[ "$JUSTONE" == "yes" ]]
        then
            # just set the most recent one for publishing
            mergefiles="$newf"
        else
            # include long-term keys, if any
            mergefiles=""
            if compgen -G "$LONGTERMKEYS" >/dev/null 2>&1
            then
                for file in $LONGTERMKEYS
                do
                    mergefiles=" $mergefiles $file"
                done
            fi
            for file in "$ECHDIR/$fehost.$feport/"*.pem.ech
            do
                fage=$(fileage "$file")
                if ((fage > durt2))
                then
                    # skip that one, we'll accept/decrypt based on that
                    # but no longer publish the public in the zone
                    continue
                fi
                mergefiles=" $mergefiles $file"
            done
        fi

        TMPF="$ECHDIR/$fehost.$feport/latest-merged"
        if [ ! -f "$TMPF" ]
        then
            actiontaken="true"
            restartactiontaken="true"
        fi
        if [[ "$actiontaken" != "false" ]]
        then
            echo "Merging these files for publication: $mergefiles"
            "$ECHDT/scripts/mergepems.sh" -o "$TMPF" $mergefiles
            echconfiglist=$(sed '/BEGIN ECHCONFIG/,/END ECHCONFIG/{//!b};d' \
                "$TMPF" | tr -d '\n')
            rm -f "$TMPF"
            echstr="\"ech\" : \"$echconfiglist\""
            ipv4str=""
            cfgips=${fe_ipv4s[${feor}]}
            if [[ "$cfgips" != "" ]]
            then
                ipv4str="\"ipv4hint\" : $(csv2jarr "$cfgips")"
            fi
            ipv6str=""
            cfgips=${fe_ipv6s[${feor}]}
            if [[ "$cfgips" != "" ]]
            then
                ipv6str="\"ipv6hint\" : $(csv2jarr "$cfgips")"
            fi
            # for a FE we don't bother with alpn
            alpnstr=""

            TMPF1=$(mktemp)
            makesvcjson "$TMPF1" "$dur" "1" \
                "$ipv4str" "$echstr" "$ipv6str" "$alpnstr"
            sudo mv "$TMPF1" "$fewkechfile"
            sudo chown "$WWWUSER:$WWWGRP" "$fewkechfile"
            sudo chmod a+r "$fewkechfile"
        fi
    done
fi

if [[ $ROLES == *"$BESTR"* ]]
then
    for beor in "${!be_arr[@]}"
    do
        echo "Checking $beor"
        bedr=${be_arr[${beor}]}
        wkechfile=$bedr/.well-known/$WESTR
        behost=$(hostport2host "$beor")
        beport=$(hostport2port "$beor")
        makecheckdir "$USER" "$USER" "$ECHDIR/$behost.$beport"
        lmf="$ECHDIR/$behost.$beport/latest-merged"
        rm -f "$lmf"
        # is there an alias entry for this BE?
        if [[ -z ${be_alias_arr[${beor}]} ]]
        then

            # non-alias case
	        # accumulate the various front-end files
            echo "Setting up service mode for $beor"
	        for feor in "${!fe_arr[@]}"
	        do
	            fehost=$(hostport2host "$feor")
	            feport=$(hostport2port "$feor")
	            TMPF=$(mktemp)
	            if [[ $ROLES == *"$FESTR"* ]]
	            then
	                # shared-mode, FE JSON file is local
	                fedr=${fe_arr[${feor}]}
	                fewkechfile=$fedr/.well-known/$WESTR
	                cp "$fewkechfile" "$TMPF"
	            else
	                # split-mode, FE JSON file is non-local
	                timeout "$CURLTIMEOUT" curl -o "$TMPF" \
                        -s "https://$feor/.well-known/$WESTR"
                    tres=$?
	                if [[ "$tres" == "124" ]]
	                then
	                    # timeout returns 124 if it timed out, or else the
	                    # result from curl otherwise
	                    echo "Timed out after $CURLTIMEOUT waiting for " \
                            "https://$feor/.well-known/$WESTR"
	                    exit 23
	                fi
	            fi
	            if [ ! -f "$TMPF" ]
	            then
	                echo "Empty result from https://$feor/.well-known/$WESTR"
	                continue
	            fi
	            # merge into latest
	            if [ ! -f "$lmf" ]
	            then
	                cp "$TMPF" "$lmf"
	            else
	                TMPF1=$(mktemp)
	                jq -n '{ endpoints: [ inputs.endpoints ] | add }' \
                        "$lmf" "$TMPF" >"$TMPF1"
	                jres=$?
	                if [[ "$jres" == 0 ]]
	                then
	                    mv "$TMPF1" "$lmf"
	                else
	                    rm -f "$TMPF1"
	                fi
	            fi
	        done
	        # add alpn info to endpoints.params, as desired
	        alpnval=${be_alpn_arr[${beor}]}
	        if [[ "$alpnval" != "" ]]
	        then
	            TMPF1=$(mktemp)
                jq --argjson p "$(csv2jarr "$alpnval")" '.endpoints[].params.alpn += $p' "$lmf" >"$TMPF1"
                jres=$?
	            if [[ "$jres" == 0 ]]
	            then
	                mv "$TMPF1" "$lmf"
	            else
	                rm -f "$TMPF1"
	            fi
	        fi

        else

            # alias case
            alvals=${be_alias_arr[${beor}]}
            echo "Setting up alias for $beor as $alvals"
            if [[ "$alvals" == "DELETE" ]]
            then
                # a signal that BE doesn't do ECH so signal we want to publish
                # an "empty" .well-known
                # TODO: is DELETE reasonable
                makealiasjson "$lmf" "$dur" ''
            else
                makealiasjson "$lmf" "$dur" "$alvals"
            fi

        fi

        newcontent=$(diff -q "$wkechfile" "$lmf")
        if [[ -f "$lmf" && "$newcontent" != "" ]]
        then
            # copy to DocRoot
            sudo cp "$lmf" "$wkechfile"
            sudo chown "$WWWUSER:$WWWGRP" "$wkechfile"
            sudo chmod a+r "$wkechfile"
            restartactiontaken="true"
        fi

    done
fi

if [[ "$restartactiontaken" != "false" ]]
then
    # restart services that support key rotation
    if [[ $ROLES == *"$FESTR"* ]]
    then
        if [[ "$FE_RESTARTER" != "" && -f $FE_RESTARTER ]]
        then
            echo "Took action - better restart frontend services"
            $FE_RESTARTER
        fi
    fi
    if [[ $ROLES == *"$BESTR"* ]]
    then
        if [[ "$BE_RESTARTER" != "" && -f $BE_RESTARTER ]]
        then
            echo "Took action - better restart backend services"
            $BE_RESTARTER
        fi
    fi
fi
THEN=$(whenisitagain)
echo "Finished $0 at $THEN (started at $NOW)"
echo "=========================================="

exit 0
