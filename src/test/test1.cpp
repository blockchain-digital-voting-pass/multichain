#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include "keys/key.h"
#include <iostream>
#include "keys/pubkey.h"




SCENARIO( "key signing and verifying", "[keys]" ) {

	GIVEN ( "A private key and correseponding public key" ) {	
		CKey key;
		key.MakeNewKey(false);

		REQUIRE ( key.IsValid() );

		WHEN ( "Signing data with the private key") {
			uint256 hash = 124657450183;
			std::vector<unsigned char> vchSig;

			REQUIRE ( key.Sign(hash, vchSig, false) );
			REQUIRE ( vchSig.size() == 320) ;

			THEN ( "The public key can verify the signature" ) {
				CPubKey pub = key.GetPubKey();
				REQUIRE ( pub.IsFullyValid() );
				REQUIRE ( pub.Verify(hash, vchSig) );
			}

		}
	}
}


SCENARIO( "private key loading", "[private key loading]" ) {

	GIVEN ( "A private key, p1" ) {	
		CKey key;
		key.MakeNewKey(false);

		REQUIRE ( key.IsValid() );

		WHEN ( "loading a new private key, p2, from p1 and signing with p2" ) {

			CKey key2(key);

			uint256 hash = 124657450183;
			std::vector<unsigned char> vchSig;
			std::vector<unsigned char> vchSig2;

			REQUIRE ( key.Sign(hash, vchSig) );
			REQUIRE ( vchSig.size() == 320);
			REQUIRE ( key2.Sign(hash, vchSig2 ) );
			REQUIRE ( vchSig2.size() == 320);
			REQUIRE ( key2 == key );

			THEN ( "this can be verified with the public key of p1" ) {
				CPubKey pub = key.GetPubKey();

				REQUIRE ( pub.IsFullyValid() );
				REQUIRE ( pub.Verify(hash, vchSig) );
				REQUIRE ( pub.Verify(hash, vchSig2) );
			}
		}
	}
}

SCENARIO( "public key loading", "[public key loading]" ) {

	GIVEN ( "A public key, p1" ) {	
		CKey key;
		key.MakeNewKey(false);
		CPubKey pub = key.GetPubKey();
		REQUIRE ( key.IsValid() );

		WHEN ( "loading a new public key, p2" ) {
			CPubKey pub2(pub.begin(), pub.end());

			uint256 hash = 124657450183;
			std::vector<unsigned char> vchSig;

			REQUIRE ( key.Sign(hash, vchSig) );
			REQUIRE ( vchSig.size() == 320);

			THEN ( "p2 can be used to verify a signature from the private key of p1" ) {
				REQUIRE ( pub.IsFullyValid() );
				REQUIRE ( pub.Verify(hash, vchSig) );
				REQUIRE ( pub2.Verify(hash, vchSig) );
				REQUIRE ( pub == pub2 );
			}
		}
	}
}



//serialize
//unserialize