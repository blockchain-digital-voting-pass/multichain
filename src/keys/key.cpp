// Copyright (c) 2009-2016 The Bitcoin developers
// Original code was distributed under the MIT software license.
// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

#include "keys/key.h"

#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "keys/pubkey.h"
#include "utils/random.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>





#include "../cryptopp/eccrypto.h"


#include "../cryptopp/sha.h"

#include "../cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "../cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "../cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "../cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "../cryptopp/integer.h"
using CryptoPP::Integer;

#include "../cryptopp/cryptlib.h"
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include <../cryptopp/hex.h>
#include "../cryptopp/asn.h"
#include "../cryptopp/osrng.h"
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

#include <stdio.h>






static secp256k1_context* secp256k1_context_sign = NULL;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80)) {
        return 0;
    }
    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end < privkey+lenb) {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;
    if (end < privkey+len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1]) {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 65;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    }
    return 1;
}

bool CKey::Check(const unsigned char *vch) {
    //IS NOT USED
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;

    //privKey.Initialize( prng, CryptoPP::ASN1::brainpoolP320r1() );
    privKey.Load(CryptoPP::StringStore((const byte*) vch,(size_t) 160).Ref());

    bool result = privKey.Validate( prng, 3 );
    return result;
    //return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    std::cout << "Calling MakeNewKey\n\n";

    //create new private key
    CryptoPP::AutoSeededRandomPool prng;
    privKey1.Initialize( prng, CryptoPP::ASN1::brainpoolP320r1() );

    //Validate the private key
    bool result = privKey1.Validate( prng, 3 );
    if(!result) {
        std::cout << "Invalid private key generated\n";
        fValid = false;
    }

    //Write the key to vch
    //TODO: rewrite this not so stupid/ugly
    CryptoPP::ByteQueue queue;
    privKey1.Save(queue);
    CryptoPP::HexEncoder encoder;
    queue.CopyTo(encoder);
    encoder.MessageEnd();
    std::string encoded;
    size_t size = encoder.MaxRetrievable();
    if(size) {
        encoded.resize(size);
    }
    encoder.Get((byte*)encoded.data(), encoded.size());
    std::cout << "Size : " << encoded.size() << "\nData: " << encoded << " END\n";

    CryptoPP::HexDecoder decoder;
    std::string decoded;
    decoder.Put( (byte*)encoded.data(), encoded.size() );
    decoder.MessageEnd();

    size = decoder.MaxRetrievable();
    if(size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)decoded.data(), decoded.size());
    }
    //write to private key
    memcpy(&vch[0], decoded.data(), decoded.size());
    //std::cout << "Decoded: " << decoded << "\nSize: " << decoded.size() << "\n";

    fValid = true;
    fCompressed = false;
}

bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn) {
    std::cout << "Set private key  FIIIIIIIX\n";
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), &privkey[0], privkey.size()))
        return false;
    fCompressed = fCompressedIn;
    fValid = true;
    return true;
}

CPrivKey CKey::GetPrivKey() const {
    std::cout << "Get priv key called FIX\n";
    std::cout << "DEze\n";
    assert(fValid);
    /*CPrivKey privkey;
    int ret;
    size_t privkeylen;
    privkey.resize(279);
    privkeylen = 279;
    ret = ec_privkey_export_der(secp256k1_context_sign, (unsigned char*)&privkey[0], &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    assert(ret);
    privkey.resize(privkeylen);*/
    CPrivKey privkey;
    privkey.resize(76);
    memcpy(&privkey[0], &vch[0], 76);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);

    CPubKey result;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
    CryptoPP::AutoSeededRandomPool prng;
    privKey1.MakePublicKey(pubKey);
    if(!pubKey.Validate(prng, 3)) {
        std::cout << "Could not construct public key from private key!\n\n";
    }
    result.Set(pubKey);

    /*if(result.IsFullyValid()) {
        std::cout << "Correct pub key\n";
    } else {
        std::cout << "Incorrect pub key\n";
    }*/

    return result;

}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    std::cout << "SIGNING\n\n";
    if (!fValid) {
        std::cout << "Signing with non valid key... Stopping\n";
        return false;
    }

    //create a signer
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privKey1);
    
    
    //signer.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::brainpoolP320r1());
    
    //validate if private key is correct
    bool result = signer.AccessKey().Validate( prng, 3 );
    if(!result) {
        std::cout << "Error in validating key\n\n";
        return false;
    }
    
    result = privKey1.Validate(prng, 3);
    if(!result) {
        std::cout << "Error in validating key\n\n";
        return false;
    }

    // Determine maximum size, allocate a string with the maximum size
    size_t siglen = signer.MaxSignatureLength();
    std::string signature(siglen * 4, 0x00);

    // Sign, and trim signature to actual size
    //siglen = signer.SignMessage( prng, (const byte*) &hash, 32, (byte*)signature.data() );
    //signature.resize(siglen);
    
    
    unsigned int i=0;
    for(i=0; i< 4; i++ ) {
        siglen = signer.SignMessage( prng, (const byte*) &hash + i*8, 8, (byte*)signature.data() + i* 80 );
        //signature.resize(siglen);
    }

    //Resize signature to make sure it is big enough
    vchSig.resize(80 * 4);

    //Copy signature to vchSig
    for(i=0; i < 80*4; i++) {
        vchSig[i] = signature[i];
    }
    //memcpy(&signature[0], &vchSig[0], siglen+1);
    
    // Resize to correct signature length
    std::cout << "Signed with key: \n";
    //printVch(true);
    //vchSig.resize(siglen);
    return true;
}

void CKey::printVch(bool oneGo) const {
    printf("Print vch:\n");
    if(!oneGo) {
        for(int i=0; i< 76; i++) {
            printf("i: %d: %02x\n", i, vch[i]);
            //i << ": ";
            //std::cout << std::hex << vch[i];
            //std::cout << "\n";
        }
    } else {
        printf("Key: ");
        for(int i=0; i< 76; i++) {
            printf("%02x", vch[i]);
        }
        printf("\n");
    }
    //std::cout << "\n";
}


bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    std::cout << "Sign Compact called FIX\n\n";
    if (!fValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, NULL);
    assert(ret);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) {
    std::cout << "Private key load called FIX \n\n";
    std::cout << "DEZE\n";
    //schrijf naar vch de key van privkey
    
    /*if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), &privkey[0], privkey.size()))
        return false;
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;
*/    
    //CryptoPP::ArraySource as((const byte*)privkey.data(), privkey.size(),
                               
       //                         true );
    memcpy(&vch[0], &privkey[0], 76);
    //privKey1.AccessKey().AccessGroupParameters().Initialize(CryptoPP::ASN1::brainpoolP320r1());
    privKey1.AccessGroupParameters().Initialize(CryptoPP::ASN1::brainpoolP320r1());
    privKey1.Load(CryptoPP::StringStore((const byte*) vch,(size_t) 76).Ref());
    //privKey1.BERDecode(as);
    fValid = true;
    //std::cout << "Valid pair: "  << VerifyPubKey(vchPubKey) << "\n";
    
    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    std::cout << "Private key derive called\n\n";
    assert(IsValid());
    assert(IsCompressed());
    unsigned char out[64];
    LockObject(out);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, out);
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), out);
    }
    memcpy(ccChild.begin(), out+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), out);
    UnlockObject(out);
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return key.Derive(out.key, out.chaincode, nChild, chaincode);
}

void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    unsigned char out[64];
    LockObject(out);
    CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(out);
    key.Set(&out[0], &out[32], true);
    memcpy(chaincode.begin(), &out[32], 32);
    UnlockObject(out);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+74, true);
}

bool ECC_InitSanityCheck() {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}


void ECC_Start() {
    assert(secp256k1_context_sign == NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];
        LockObject(seed);
        GetRandBytes(seed, 32);
        bool ret = secp256k1_context_randomize(ctx, seed);
        assert(ret);
        UnlockObject(seed);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = NULL;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
