CXX=g++
CXXFLAGS=-O2 -fpatchable-function-entry=16,14 -fdump-ipa-clones -fPIC -g3
ULP=/usr/bin/ulp
LDFLAGS=

all: test a_livepatch1.so

test: test.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.so: %.o %.dsc
	$(CXX) $(CXXFLAGS) -shared -o $@ $<
	$(ULP) packer $(word 2, $^)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

clean:
	rm -f test *.o *.so *.ipa-clones

clena: clean
