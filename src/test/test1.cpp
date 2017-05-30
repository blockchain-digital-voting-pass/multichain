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


SCENARIO( "CPrivKey", "[public key loading]" ) {

	GIVEN ( "A CPrivKey" ) {	
		CKey key;
		key.MakeNewKey(false);
		CPubKey pubKey = key.GetPubKey();
		CPrivKey privKey = key.GetPrivKey();

		REQUIRE( pubKey.IsFullyValid() );
		WHEN ( "when loading from a CKey from this CPrivKey, p2" ) {
			
			
			THEN ( "public key is correct..." ) {
                CKey keyLoad;
                REQUIRE ( keyLoad.Load(privKey, pubKey, false) );
                REQUIRE ( keyLoad.Load(privKey, pubKey, true) );
			}
		}
	}
}

SCENARIO( "Wrong signature", "[signature]" ) {

	GIVEN ( "A wrong signature" ) {	
		CKey key;
		key.MakeNewKey(false);

		REQUIRE ( key.IsValid() );

		WHEN ( "verifying this signature" ) {
			uint256 hash = 124657450183;
			std::vector<unsigned char> vchSig;

			REQUIRE ( key.Sign(hash, vchSig) );
			REQUIRE ( vchSig.size() == 320);
			
			//get public key
            CPubKey pub = key.GetPubKey();
            REQUIRE ( pub.IsFullyValid() );
    
			THEN ( "the signature is considered incorrect" ) {
                //Invalidate signature
                vchSig[20] = vchSig[20] ^ 1;			    
				REQUIRE ( pub.Verify(hash, vchSig) == false);
                //switch byte back
                vchSig[20] = vchSig[20] ^ 1;
                REQUIRE ( pub.Verify(hash, vchSig) );

			}
			THEN ( "the signature is considered incorrect" ) {
				vchSig.clear();
				vchSig.resize(0);
				REQUIRE ( pub.Verify(hash, vchSig) == false);
			}
		}
	}
}

SCENARIO( "Invalid CKey", "[public key loading]" ) {

	GIVEN ( "An invalid CKey" ) {	
		CKey key;
		key.MakeNewKey(false);
		
		std::vector<unsigned char> invalidKey;
		invalidKey.resize(CRYPTOPP_PRIVATE_KEY_SIZE);
		invalidKey[0] = 'a';
		
		key.Set(invalidKey.begin(), invalidKey.end(), false);
		WHEN ( " signing data " ) {
            uint256 hash = 124657450183;
			std::vector<unsigned char> vchSig;
	
			THEN ( " the sign function will return false" ) {
			    REQUIRE( key.Sign(hash, vchSig) == false);
			}
		}
	}
}

SCENARIO( "Invalid CPubKey", "[public key loading]" ) {

	GIVEN ( "An invalid CPubKey" ) {	
	    CPubKey pub;
	    		
		std::vector<unsigned char> invalidKey;
		invalidKey.resize(CRYPTOPP_PUBLIC_KEY_SIZE);
		invalidKey[0] = 'a';
            
		pub.Set(invalidKey.begin(), invalidKey.end());
        uint256 hash = 124657450183;
        std::vector<unsigned char> vchSig;
        vchSig.resize(CRYPTOPP_SIGNATURE_SIZE * 4);
		
		REQUIRE( pub.IsValid() == false );
		REQUIRE( pub.IsFullyValid() == false );
		WHEN ( " this CPubkey has a invalid header " ) {
	
			THEN ( " the verify function will return false" ) {
			    REQUIRE( pub.Verify(hash, vchSig) == false);
			}
		}
		
        WHEN ( " this CPubKey has a correct header " ) {
            invalidKey[0] = 0x30; 
            pub.Set(invalidKey.begin(), invalidKey.end());
            
			THEN ( " the key is invalidated" ) {
                REQUIRE( pub.IsValid() == false);
			}
            
            
        }

		
	}
}

