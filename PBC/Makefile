SRCS=$(wildcard *.cc)
OBJS=$(subst .cc,.o,$(SRCS))

#CXXFLAGS=-m32 -g -O2 -Wall
CXXFLAGS=-g -O2 -Wall -D_GLIBCXX_USE_CXX11_ABI=1

all: libPBC.a Testing

COMMON_OBJS=Pairing.o G.o G1.o G2.o GT.o Zr.o PPPairing.o

libPBC.a: $(COMMON_OBJS)
	ar rcs $@ $^

Testing: Testing.o libPBC.a
#g++ -m32 -g -static -o $@ $^ -lpbc -lgmp
	g++ -g -static -o $@ $^ -lpbc -lgmp

clean:
	-rm -f $(OBJS)

depend:
	makedepend -Y -- $(CXXFLAGS) -- $(SRCS) 2>/dev/null


# DO NOT DELETE

G1.o: G1.h G.h Pairing.h Zr.h PBCExceptions.h
G2.o: G2.h G.h Pairing.h Zr.h PBCExceptions.h
G.o: G.h Pairing.h Zr.h PBCExceptions.h
GT.o: GT.h G.h Pairing.h Zr.h PBCExceptions.h
Pairing.o: Pairing.h G1.h G.h Zr.h G2.h GT.h PBCExceptions.h
PPPairing.o: PPPairing.h Pairing.h G1.h G.h Zr.h G2.h GT.h PBCExceptions.h
Testing.o: PBC.h G1.h G.h Pairing.h Zr.h G2.h GT.h PBCExceptions.h
Testing.o: PPPairing.h
Zr.o: Zr.h Pairing.h PBCExceptions.h
