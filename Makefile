esrc := $(wildcard src/*.erl)
ebin := $(patsubst src/%.erl,ebin/%.beam,$(esrc))

comma := ,
empty :=
space := $(empty) $(empty)
modules := $(subst $(space),$(comma),$(patsubst src/%.erl,%,$(esrc)))

all: $(ebin) ebin/proxypal.app

$(ebin): ebin.STAMP

ebin.STAMP: $(esrc)
	erl -make
	touch ebin.STAMP

ebin/proxypal.app: src/proxypal.app.src
	sed -e 's/@MODULES@/$(modules)/' \
	    src/proxypal.app.src > ebin/proxypal.app

priv/bin/get_proxy: c_src/get_proxy.o
	$(CC) $(LDFLAGS) $(LDADD) -o priv/bin/get_proxy c_src/get_proxy.o -lproxy

clean:
	rm -f ebin/* c_src/*.o ebin.STAMP
