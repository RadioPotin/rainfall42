#!/bin/bash

check_sshpass() {
	if [ ! -x "$(which sshpass)" ] ; then
		echo -e "\nYou must ensure that sshpass is installed and in your \$PATH first. Exiting ...";
		exit 1;
	fi
}

check_sshpass

usage() {
	cat <<- EOF
		usage: $0 options

		This script setup peda on a designated VM ip.

		OPTIONS:
		   -h    Show this message
		   -s    Server IP
		   -u    User on target (Default level0)
		   -x    Password for user (Default level0)
		   -p    Server Port (Default 4242)
	EOF
}

IP=''
USER='level0'
PASSWORD='level0'
PORT='4242'
while getopts 'hs:p:u:x:' OPTION; do
	case $OPTION in
		h) usage; exit 1;;
		u) USER=$OPTARG;;
		s) IP=$OPTARG;;
		x) PASSWORD=$OPTARG;;
		p) PORT=$OPTARG;;
	esac
done

if [ -z "$USER" ] || [ -z "$IP" ] || [ -z "$PASSWORD" ] ; then
	usage
	exit 1
fi

info() {
	cat <<- EOF
		Installing peda on $USER@$IP:$PORT ...
	EOF
}

info

setup() {
	echo -e "\nCreating /tmp/peda ...\n"
	set -o xtrace
	sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$IP -p $PORT 'if [ ! -e /tmp/peda ]; then mkdir /tmp/peda; fi'
	set +o xtrace
	echo -e "\nAdding correct permissions to /tmp/peda ...\n"
	set -o xtrace
	sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$IP -p $PORT 'chmod 777 /tmp/peda'
	set +o xtrace
	echo -e "\nCloning Peda locally ...\n"
	set -o xtrace
	if [ ! -e peda ]; then
		git clone https://github.com/longld/peda.git
	fi
	set +o xtrace
	echo -e "\nCopying Peda to /tmp/peda ...\n"
	set -o xtrace
	sshpass -p "$PASSWORD" scp -r -P $PORT -o StrictHostKeyChecking=no peda $USER@$IP:/tmp/
	set +o xtrace
	echo -e "\nConfiguring ~/.gdbinit ...\n"
	set -o xtrace
	sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no $USER@$IP -p $PORT 'chmod +rwx ~; echo "source /tmp/peda/peda.py" > ~/.gdbinit'
	set +o xtrace
}

setup

exit 0
