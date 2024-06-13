BIN=disas
PREFIX=/usr/local

CXX=g++
CXXFLAGS=-O2 -std=c++20
LDFLAGS=-lcapstone

all: $(BIN)

$(BIN): ./src/main.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

%.o: ./src/%.cpp
	$(CXX) $(CXXFLAGS) -c $(LDFLAGS) $^

install:
	cp ./$(BIN) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f ./$(BIN) *.o

.PHONY: clean
