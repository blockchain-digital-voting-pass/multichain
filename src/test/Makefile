HEADERS =  test1.o catch.hpp ../structs/amount.h ../keys/key.h ../keys/pubkey.h \
  ../structs/hash.h ../crypto/ripemd160.h ../crypto/sha256.h \
 ../utils/serialize.h ../structs/uint256.h ../version/bcversion.h \
 ../utils/allocators.h ../crypto/common.h ../crypto/hmac_sha512.h \
 ../crypto/sha512.h ../utils/utilstrencodings.h ../utils/random.h \
 ../utils/util.h ../utils/utiltime.h ../chainparams/chainparamsbase.h \
 ../chainparams/params.h  \
 ../version/version.h ../multichain/multichain.h \
 ../primitives/block.h ../chainparams/globals.h ../utils/streams.h \
 ../version/clientversion.h

SOURCES =../keys/pubkey.cpp \
 ../keys/key.cpp ../crypto/sha256.cpp ../structs/hash.cpp ../crypto/ripemd160.cpp \
 ../structs/uint256.cpp ../utils/allocators.cpp ../crypto/hmac_sha512.cpp \
 ../crypto/sha512.cpp ../utils/utilstrencodings.cpp ../utils/random.cpp \
 ../utils/util.cpp ../utils/utiltime.cpp ../chainparams/chainparamsbase.cpp \
 ../utils/utilwrapper.cpp ../utils/tools.cpp ../chainparams/params.cpp \
 ../utils/utility.cpp ../utils/systemdependent.cpp ../version/version.cpp \
 ../structs/amount.cpp



COV=-fprofile-arcs -ftest-coverage

LIB=-lcryptopp -lcrypto \
	-lboost_thread -lboost_filesystem \
	-lboost_system -lboost_program_options -lpthread 
INC=-I../ \
	-I../secp256k1/ \
	-I../secp256k1/include/


FLAGS=-DHAVE_DECL_STRNLEN -DHAVE_WORKING_BOOST_SLEEP_FOR -DUNIT_TESTING_MULTICHAIN

STATIC_LIBS = ../secp256k1/.libs/libsecp256k1.a


NAME=tst.o


default : comp go 

#test: test1.cpp
#	g++ -c test1.cpp -I../ -lcryptopp -o $(NAME)

comp: test1.cpp
	g++ -c test1.cpp -I../ $(COV)

go: test1.cpp 
	g++  $(FLAGS) $(COV) $(HEADERS) $(SOURCES) $(LIB) $(INC)   $(STATIC_LIBS) 
