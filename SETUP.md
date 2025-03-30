# Setting up the run-time environment for the zone-factory scripts

The zone-factory script code depends on specific features of both both
OpenSSL and Python, currently provided in custom forks of the
respective codebases (cpython for Python), which may be built as shown
here.

## Style

Building, installing, and demonstrating software depends on individual
style. The instructions here reflect some specific preferences of the
author:

- Building the software in a directory tree other than the source tree;

- Adhering to the "configure/make/install" workflow so that dependent
  software can be built without making run-time reference to the build
  directory tree of each dependency.

## Instructions

These instructions are expected to be suitable for any POSIX-compliant
command shell.

1.  Specify directory trees to use

	-   Optionally, specify a build directory tree outside the source tree
		```
		BLD_BASE=$HOME/build
		```

	-   Specify the source, build, and installation directory trees
		```
		SRC_BASE=$HOME/repo
		: ${BLD_BASE:=$SRC_BASE}
		INS_BASE=$HOME/installed
		```

2.  Set up the source directory trees

    -   Clone the custom fork of OpenSSL 
		```
		mkdir $SRC_BASE/defo-project
		git -C $SRC_BASE/defo-project \
			clone https://github.com/defo-project/openssl
		```
	
	-   Clone the custom fork of cpython
		```
		mkdir $SRC_BASE/irl
		git -C $SRC_BASE/irl \
			clone https://github.com/irl/cpython
		```
	
	-   Select the required branch of each custom fork
		```
		git -C $SRC_BASE/defo-project checkout master
		git -C $SRC_BASE/irl/cpython checkout ech
		```

3.  Build and install OpenSSL

	-   Specify directory sub-trees for building and installing OpenSSL
		```
		BLD_DIR=$BLD_BASE/defo-project/openssl
		SRC_DIR=$SRC_BASE/defo-project/openssl
		INS_DIR=$INS_BASE/defo-project
		```

	-   Configure and install OpenSSL
		```
		( cd $BLD_DIR \
			&& env LDFLAGS=-Wl,-rpath,$INS_DIR/lib \
				$SRC_DIR/config \
				--prefix=$INS_DIR --libdir=lib ) \
	    && make -C $BLD_DIR install_sw
		```

4.  Build and install cpython

	-   Specify directory sub-trees to use for building cpython
		```
		BLD_DIR=$BLD_BASE/defo-dev/cpython
		SRC_DIR=$SRC_BASE/irl/cpython
		INS_DIR=$INS_BASE/defo-dev
		```

	-   Populate build directory tree if outside source tree
		```
		tar -C $SRC_DIR -cf - . | tar -C $BLD_DIR -xpBf - 
		chmod 0755 "$BLD_DIR"
		```

	-   Configure and install cpython
		```
		( cd $BLD_DIR \
			&& $BLD_DIR/configure \
				--prefix=$INS_DIR \
				--with-openssl=$INS_BASE/defo-project \
				--with-openssl_rpath=auto )
	    make -C $BLD_DIR install
		```

5.  Configure and activate Python virtual environment using installed cpython
	```
	$INS_BASE/defo-dev/bin/python3 -m venv dev
	. dev/bin/activate
	```

6.  Install required Python packages
	```
	pip install certifi dnspython httptools
	```

7.  Try out the only zone-factory script currently available
	```
	python3 ./updzone-from-wkech.py -h
	python3 ./updzone-from-wkech.py fetch https://defo.ie/
	python3 ./updzone-from-wkech.py -v fetch https://defo.ie/
	```
