SiriDB Server
=============

SiriDB (C-implementation)

Installation
------------

Compiled packages are available for Ubuntu (amd64 - 16.04 LTS xenial)

	wget https://github.com/transceptor-technology/siridb-server/releases/download/2.0.12/siridb-server_2.0.12_amd64.deb
	sudo dpkg -i siridb-server_2.0.12_amd64.deb
	
For creating a new or joining an existing database you need the manage tool:

	wget https://github.com/transceptor-technology/siridb-manage/releases/download/2.0.1/siridb-manage_2.0.1_amd64.deb
	sudo dpkg -i siridb-manage_2.0.1_amd64.deb
	
If you like to manage SiriDB from the terminal we have a prompt with auto-completion support available:

	wget https://github.com/transceptor-technology/siridb-prompt/releases/download/2.0.2/siridb-prompt_2.0.2_amd64.deb
	sudo dpkg -i siridb-prompt_2.0.2_amd64.deb


Compile
-------

(Ubuntu) Install the following packages:
 
	sudo apt install libuv1-dev
	sudo apt install uuid-dev
	sudo apt install libpcre3-dev

Replace `Release` with `Debug` for a debug build.

	cd ./Release
	make clean
	make


Build Deb Package
-----------------	

(Ubuntu) Install the following packages:

    sudo apt install libpcre3-dev
    sudo apt install libuv1-dev
    sudo apt install uuid-dev
    sudo apt install python3-setuptools
    sudo apt install devscripts
    sudo apt install dh-make
    sudo apt install debhelper
    sudo apt install pkg-config
    sudo apt install dh-autoreconf
    sudo apt install dh-exec


Logging
-------
Journal is prefered over rsyslog. To setup persistant logging using journald:
`sudo mkdir -p /var/log/journal`

Modify `/etc/systemd/journald.conf` and enable the following:

	[Journal]
	Storage=persistent
	
