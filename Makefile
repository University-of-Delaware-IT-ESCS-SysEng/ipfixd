BASEFILE=ipfixd
SENDFILE=send
BASE_PYTHON=python3.11
VERSION=1.0.0
PREFIX=/usr/local
PREFIX_APP_ROOT:=${PREFIX}/apps/ipfixd-${VERSION}
PREFIX_APP_ENV:=${PREFIX_APP_ROOT}/env
PREFIX_APP_BIN:=${PREFIX_APP_ROOT}/bin
PREFIX_APP:=${PREFIX_APP_ROOT}/ipfixd_app

PROD_BIN:=${PREFIX}/bin/${BASEFILE}

SRCS=\
	ipfixd_app/args.py \
	ipfixd_app/byte_mover.pyx \
	ipfixd_app/byte_mover.pxd \
	ipfixd_app/header.pyx \
	ipfixd_app/cflowd.py \
	ipfixd_app/__init__.py \
	ipfixd_app/ipfixd_log.py \
	ipfixd_app/ipfixd_profile.py \
	ipfixd_app/ipfixd_queue.py \
	ipfixd_app/ipfixd_thread.py \
	ipfixd_app/ipfix.py \
	ipfixd_app/main.py \
	ipfixd_app/netflow_v10.py \
	ipfixd_app/netflow_v5.py \
	ipfixd_app/packet.py \
	ipfixd_app/sockets.py \
	ipfixd_app/util.py \
	ipfixd_app/writer.py

LIBS=\
	ipfixd_app/byte_mover.cpython-311-x86_64-linux-gnu.so \
	ipfixd_app/header.cpython-311-x86_64-linux-gnu.so

MODULES=${SRCS} ${LIBS}

env: bin
	rm -rf env/
	${BASE_PYTHON} -m venv env
	env/bin/python -m pip install -r requirements.txt

bin:
	echo '#!/bin/bash' > ${BASEFILE}
	echo "env PYTHONPATH=${PWD} ${PWD}/env/bin/python -m ipfixd_app.main "$$\* >> ${BASEFILE}
	chmod 775 ${BASEFILE}
	echo '#!/bin/bash' > ${SENDFILE}
	echo "env PYTHONPATH=${PWD} ${PWD}/env/bin/python -m send "$$\* >> ${SENDFILE}
	chmod 775 ${SENDFILE}

libs:
	${PWD}/env/bin/python3 setup.py build_ext --inplace

install:

#
# This should run using an non-root account.  Just give yourself
# access to the PREFIX_APP_ROOT directory.  After installation,
# run make ownership and make activate as root.
# 

	UMASK=`umask`
	umask 222

	if [ -d ${PREFIX_APP_ROOT} ]; then \
		rm -rf ${PREFIX_APP_ROOT}; \
	fi

	for i in ${PREFIX_APP_ROOT} \
		${PREFIX_APP_ENV} \
		${PREFIX_APP_BIN} \
		${PREFIX_APP}; do \
		mkdir $${i}; \
		chmod 755 $${i}; \
	done

# Make a shell script that starts Python isolated from the user environment
## and invokes our main module with a modified path.

	echo "#!${PREFIX_APP_ENV}/bin/python -I" > ${PREFIX_APP_BIN}/${BASEFILE}
	echo "import sys" >> ${PREFIX_APP_BIN}/${BASEFILE}
	echo "sys.path.append( '${PREFIX_APP_ROOT}' )" >> ${PREFIX_APP_BIN}/${BASEFILE}
	echo "import ipfixd_app.main" >> ${PREFIX_APP_BIN}/${BASEFILE}
	chmod 555 ${PREFIX_APP_BIN}/${BASEFILE}

	cp ${MODULES} ${PREFIX_APP}/

# These are not directly part of the app, they control targets created for
# the app.

	cp requirements.txt ${PREFIX_APP_ROOT}/
	cp setup.py ${PREFIX_APP_ROOT}/

#
# Make the environment and install some packages so we get
# latest versions of install programs.
#
	${BASE_PYTHON} -m venv ${PREFIX_APP_ENV}
	${PREFIX_APP_ENV}/bin/python -m pip install --upgrade pip
	${PREFIX_APP_ENV}/bin/python -m pip install --upgrade wheel
	${PREFIX_APP_ENV}/bin/python -m pip install --upgrade setuptools
	${PREFIX_APP_ENV}/bin/python -m pip install -r ${PREFIX_APP_ROOT}/requirements.txt

# Run Cython and create the libraries.

	${PREFIX_APP_ENV}/bin/python ${PREFIX_APP_ROOT}/setup.py build_ext --inplace

	${PREFIX_APP_BIN}/${BASEFILE} --help < /dev/null
	umask ${UMASK}

ownership:
	chown -RPv root:root ${PREFIX_APP_ROOT}/.

activate:
	ln -sf ${PREFIX_APP_BIN}/${BASEFILE} ${PROD_BIN}


#
# You probably only want to do this once.
#
# systemctl enable ipfixd
# systemctl start ipfixd
#

systemd:
	mkdir -p /etc/ipfixd
	chown root:root /etc/ipfixd
	chmod 770 /etc/ipfixd

	echo "LOG=local1" > /etc/ipfixd/ipfixd.conf
	chown root:root /etc/ipfixd/ipfixd.conf
	chmod 660 /etc/ipfixd/ipfixd.conf

	cp ipfixd.service /etc/systemd/system/
	chown root:root /etc/systemd/system/ipfixd.service
	systemctl daemon-reload

clean:
	rm -rf build/*
	rm -r ipfixd_app/*.so

