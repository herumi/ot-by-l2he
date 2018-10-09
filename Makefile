CPPFLAGS=-Ofast -Wall -Wextra -I../mcl/include -I../cybozulib/include -fopenmp
#CPPFLAGS=-g -Wall -Wextra -I../mcl/include -I../cybozulib/include
LDFLAGS=-L../mcl/lib -lmcl -lgmpxx -lgmp -lcrypto
TARGET=ot.cgi enc dec
all:$(TARGET)

ot.cgi: ot.cpp util.hpp
	$(CXX) -o $@ ot.cpp $(CPPFLAGS) $(LDFLAGS)

enc: enc.cpp util.hpp
	$(CXX) -o $@ enc.cpp $(CPPFLAGS) $(LDFLAGS)

dec: dec.cpp util.hpp
	$(CXX) -o $@ dec.cpp $(CPPFLAGS) $(LDFLAGS)

test_cgi: $(TARGET)
	./enc 0 | ./ot.cgi -t | ./dec
	./enc 1 | ./ot.cgi -t | ./dec
	./enc 2 | ./ot.cgi -t | ./dec
	./enc 3 | ./ot.cgi -t | ./dec

test_js: ./ot.cgi
	cd html && node test

test:
	$(MAKE) test_cgi
	$(MAKE) test_js

clean:
	rm -rf $(TARGET)
