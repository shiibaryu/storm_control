iproute2-src = iproute2-4.19.0
subdirs = k_mod $(iproute2-src) 


all:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i; \
	done

install:
	for i in kmod $(iproute2-src); do \
		echo; echo $$i; \
		make -C $$i install; \
	done

clean:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i clean; \
	done
