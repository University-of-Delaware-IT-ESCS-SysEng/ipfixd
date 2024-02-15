BASE_PYTHON=python3.11
BASEFILE=ipfixd
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
	ipfixd_app/byte_mover.cpython-38-x86_64-linux-gnu.so \
	ipfixd_app/header.cpython-38-x86_64-linux-gnu.so

clean:
	rm -rf build/*
	rm -r ipfixd_app/*.so

TGT=/usr/local/netflow
BIN=$(TGT)/bin
APP=$(BIN)/ipfixd_app

bin:
	echo '#!/bin/bash' > ${BASEFILE}
	echo "env PYTHONPATH=${PWD} ${PWD}/env/bin/python -m ga_app.ga "$$\* >> ${BASEFILE}
	chmod 775 ${BASEFILE}

env: bin
	rm -rf env/
	${BASE_PYTHON} -m venv env
	env/bin/python -m pip install -r requirements.txt

libs:
	${PWD}/env/bin/python3 setup.py build_ext --inplace

install:
	for i in $(TGT) $(BIN) $(APP); do \
		mkdir -p $${i};\
		chown root:root $${i};\
		chmod 755 $${i};\
	done
	cp -p $(SRCS) $(APP)
	cp -p $(LIBS) $(APP)
	chown root:root $(APP)/*
	chmod 644 $(APP)/*
	for i in $(LIBS); do \
		chmod 755 $${i};\
	done
	cp -p ipfixd $(BIN)
	chown root:root $(BIN)/ipfixd
	chmod 755 $(BIN)/ipfixd
	$(BIN)/ipfixd --help
