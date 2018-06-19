esrc := $(wildcard src/*.erl)
ebin := $(patsubst src/%.erl,ebin/%.beam,$(esrc))

comma := ,
empty :=
space := $(empty) $(empty)
modules := $(subst $(space),$(comma),$(patsubst src/%.erl,%,$(esrc)))

all: $(ebin) ebin/proxypal.app priv/bin/get_proxy

$(ebin): ebin.STAMP

ebin.STAMP: $(esrc) src/linux_socket.hrl
	mkdir -p ebin
	erl -make
	touch ebin.STAMP

ebin/proxypal.app: src/proxypal.app.src
	sed -e 's/@MODULES@/$(modules)/' \
	    src/proxypal.app.src > ebin/proxypal.app

priv/bin/get_proxy: c_src/get_proxy.o
	mkdir -p priv/bin
	$(CC) $(LDFLAGS) $(LDADD) -o priv/bin/get_proxy c_src/get_proxy.o -lproxy -lcap

clean:
	rm -f ebin/* c_src/*.o ebin.STAMP
