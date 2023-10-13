CXX=g++
CXXFLAGS=-O2 -fpatchable-function-entry=16,14 -fPIC -g3
ULP=$(shell which ulp 2>/dev/null)
LDFLAGS=

ifeq ($(ULP),)
$(error Not found ulp, please make install first)
endif

all: test a_livepatch1.so

test: class.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.so: %.o %.dsc
	$(CXX) $(CXXFLAGS) -shared -o $@ $<
	$(ULP) packer $(word 2, $^)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

clean:
	rm -f test *.o *.so

clena: clean
