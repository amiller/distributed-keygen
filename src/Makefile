SRCS=$(wildcard *.cc)
OBJS=$(subst .cc,.o,$(SRCS))

#CXXFLAGS=-m32 -g -O0 -Wall -I..
CXXFLAGS=-g -O0 -Wall -I.. -D_GLIBCXX_USE_CXX11_ABI=1

all: node BLSclient

COMMON_OBJS=application.o networkmessage.o usermessage.o buddy.o \
		buddyset.o systemparam.o bipolynomial.o polynomial.o lagrange.o \
		commitment.o commitmentmatrix.o commitmentvector.o io.o timer.o message.o

node: node.o $(COMMON_OBJS)
	g++ -g -o $@ $^ -L../PBC -lPBC -lpthread -lgnutls -lpbc -lgmp -lgcrypt -lgpg-error -ltasn1 -lz

BLSclient: blsclient.o $(COMMON_OBJS)
	g++ -g -o $@ $^ -L../PBC -lPBC -lpthread -lgnutls -lpbc -lgmp -lgcrypt -lgpg-error -ltasn1 -lz

polytest: polytest.o bipolynomial.o polynomial.o lagrange.o systemparam.o
	g++ g -o $@ $^ -L../PBC -lPBC -lpthread -lgnutls -lpbc

commitmentmatrix:  commitmentmatrix.o bipolynomial.o polynomial.o io.o \
	systemparam.o lagrange.o
	g++ -g -o $@ $^ -L../PBC -lPBC -lpthread -lgnutls -lpbc

commitmentvector:  commitmentvector.o bipolynomial.o polynomial.o io.o \
	systemparam.o lagrange.o
	g++ -g -o $@ $^ -L../PBC -lPBC -lpthread -lgnutls -lpbc

clean:
	-rm -f $(OBJS)

depend:
	makedepend -Y -- $(CXXFLAGS) -- $(SRCS) 2>/dev/null

# DO NOT DELETE

application.o: application.h systemparam.h ../PBC/PBC.h ../PBC/G1.h
application.o: ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
application.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h
application.o: exceptions.h buddyset.h buddy.h networkmessage.h message.h
application.o: commitment.h commitmentvector.h bipolynomial.h polynomial.h
application.o: commitmentmatrix.h io.h usermessage.h timer.h timermessage.h 
bipolynomial.o: bipolynomial.h polynomial.h systemparam.h ../PBC/PBC.h
bipolynomial.o: ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h
bipolynomial.o: ../PBC/G2.h ../PBC/GT.h ../PBC/PBCExceptions.h
bipolynomial.o: ../PBC/PPPairing.h exceptions.h
blsclient.o: application.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
blsclient.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
blsclient.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h
blsclient.o: buddyset.h buddy.h networkmessage.h message.h commitment.h
blsclient.o: commitmentvector.h bipolynomial.h polynomial.h
blsclient.o: commitmentmatrix.h io.h usermessage.h lagrange.h 
buddy.o: buddyset.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
buddy.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
buddy.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h buddy.h
buddy.o: networkmessage.h message.h commitment.h commitmentvector.h
buddy.o: bipolynomial.h polynomial.h commitmentmatrix.h 
buddyset.o: buddyset.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
buddyset.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
buddyset.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h buddy.h
buddyset.o: networkmessage.h message.h commitment.h commitmentvector.h
buddyset.o: bipolynomial.h polynomial.h commitmentmatrix.h 
commitment.o: commitment.h commitmentvector.h systemparam.h ../PBC/PBC.h
commitment.o: ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
commitment.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h
commitment.o: exceptions.h bipolynomial.h polynomial.h commitmentmatrix.h
commitment.o: io.h buddyset.h buddy.h networkmessage.h message.h lagrange.h 
commitmentmatrix.o: commitmentmatrix.h systemparam.h ../PBC/PBC.h ../PBC/G1.h
commitmentmatrix.o: ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
commitmentmatrix.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h
commitmentmatrix.o: exceptions.h bipolynomial.h polynomial.h io.h buddyset.h
commitmentmatrix.o: buddy.h networkmessage.h message.h commitment.h
commitmentmatrix.o: commitmentvector.h 
commitmentvector.o: commitmentvector.h systemparam.h ../PBC/PBC.h ../PBC/G1.h
commitmentvector.o: ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
commitmentvector.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h
commitmentvector.o: exceptions.h bipolynomial.h polynomial.h io.h buddyset.h
commitmentvector.o: buddy.h networkmessage.h message.h commitment.h
commitmentvector.o: commitmentmatrix.h 
io.o: io.h buddyset.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
io.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
io.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h buddy.h
io.o: networkmessage.h message.h commitment.h commitmentvector.h
io.o: bipolynomial.h polynomial.h commitmentmatrix.h 
lagrange.o: lagrange.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h
lagrange.o: ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h ../PBC/PBCExceptions.h
lagrange.o: ../PBC/PPPairing.h 
message.o: message.h
networkmessage.o: networkmessage.h message.h buddyset.h systemparam.h
networkmessage.o: ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h
networkmessage.o: ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h ../PBC/PBCExceptions.h
networkmessage.o: ../PBC/PPPairing.h exceptions.h buddy.h commitment.h
networkmessage.o: commitmentvector.h bipolynomial.h polynomial.h
networkmessage.o: commitmentmatrix.h io.h 
node.o: application.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
node.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
node.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h buddyset.h
node.o: buddy.h networkmessage.h message.h commitment.h commitmentvector.h
node.o: bipolynomial.h polynomial.h commitmentmatrix.h io.h usermessage.h
node.o: timer.h timermessage.h 
polynomial.o: polynomial.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
polynomial.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
polynomial.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h 
polytest.o: bipolynomial.h polynomial.h systemparam.h ../PBC/PBC.h
polytest.o: ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
polytest.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h
polytest.o: exceptions.h 
recovery.o: polynomial.h systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
recovery.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
recovery.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h lagrange.h 
systemparam.o: systemparam.h ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h
systemparam.o: ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h
systemparam.o: ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h 
timer.o: timer.h timermessage.h message.h systemparam.h ../PBC/PBC.h
timer.o: ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h ../PBC/Zr.h ../PBC/G2.h
timer.o: ../PBC/GT.h ../PBC/PBCExceptions.h ../PBC/PPPairing.h exceptions.h 
usermessage.o: usermessage.h message.h io.h buddyset.h systemparam.h
usermessage.o: ../PBC/PBC.h ../PBC/G1.h ../PBC/G.h ../PBC/Pairing.h
usermessage.o: ../PBC/Zr.h ../PBC/G2.h ../PBC/GT.h ../PBC/PBCExceptions.h
usermessage.o: ../PBC/PPPairing.h exceptions.h buddy.h networkmessage.h
usermessage.o: commitment.h commitmentvector.h bipolynomial.h polynomial.h
usermessage.o: commitmentmatrix.h 
