const ExpandSecp256k1CryptoSuite = require('./ExpandSecp256k1CryptoSuite')
const didAuth = require('@decentralized-identity/did-auth-jose');
const EcPublicKey = require('./ExpandEcPublicKey');
const EcPrivateKey = require('./ExpandEcPrivateKey');
const NodeRSA = require('node-rsa');
var getPem = require('rsa-pem-from-mod-exp');
var pem2jwk = require('pem-jwk').pem2jwk
var jwk2pem = require('pem-jwk').jwk2pem
//var ecdh = require('ecdh-es');

const privateKeyHex = '1b9b870790d3f153112be5b38905c70044e6a7dda9e51b7360f466f3577cb08f';
const publicKeyHex = '04a212250307bd5b4439f974990cba0c70b649065743f2d0e647e95e80be5d4d390d234384fe71b7198695290b0b8a14c6137f9700becd8f7de95d50e23c03f3e6';

const privateKeyHex2 = 'b98b880698ab7c156702a4005a632a6ffbc3646779fbcf139b1726bf86895dce';
const publicKeyHex2 = '042d7839683830fb8bf9de8c2e3b7f42d424ce1534b1e27bb387a3b3c221a239b5ea2c1f0c1554c412340507c68428d12007d49c4e4c11d72f86a61b0c065dc938';

/**
 * Did doucument public key 와 Encoded key 간의 변환 테스트
 */
function KeyTest() {
    console.log();
    console.log();
    console.log("===================== EcKey Testing");

    // private key test
    var ecPrivateKey = EcPrivateKey.from('did:meta:0x00035#0x1b9b870790d3f153112be5b38905c70044e6a7dda9e51b7360f466f3577cb08f', privateKeyHex, 'hex');
    console.log('PrivateKeyHex : '+privateKeyHex);
    console.log('PrivateKeyJwk : '+JSON.stringify(ecPrivateKey));
    console.log('JwkToPrivateKeyHex : '+ecPrivateKey.toPrivateKey('hex'));

    // public key test
    console.log('PublicKeyHex : '+publicKeyHex);
    var ecPublicKey = EcPublicKey.from('did:meta:test#e3333', publicKeyHex, 'hex');
    console.log('PublicKeyJwk : '+JSON.stringify(ecPublicKey));
    console.log('JwkToPublicKeyHex : '+ecPublicKey.toPublicKey('hex'));
}

/**
 * Secp256k1CryptoSuite 의 encrypt/decrypt, sign/verify test
 */
async function Secp256k1CryptoSutieTest() {
    var suite = new ExpandSecp256k1CryptoSuite();
    const ecPrivateKey = EcPrivateKey.from('did:meta:0x00035#0x1b9b870790d3f153112be5b38905c70044e6a7dda9e51b7360f466f3577cb08f', privateKeyHex, 'hex');
    const ecPublicKey = EcPublicKey.from('did:meta:0x00035#0x1b9b870790d3f153112be5b38905c70044e6a7dda9e51b7360f466f3577cb08f', publicKeyHex, 'hex');
    const message = 'Test ECIES';

    console.log();
    console.log();
    console.log("===================== Secp256k1CryptoSuite encrypt/decrypt Testing");
    console.log('Message : '+message);
    var encryptedMessage = await suite.getEncrypters().ECIES.encrypt(message, ecPublicKey);
    console.log("Encrypted Message : "+encryptedMessage.toString('base64'));
    var decryptedMessage = await suite.getEncrypters().ECIES.decrypt(encryptedMessage, ecPrivateKey);
    console.log("Decrypted Message : "+decryptedMessage.toString());

    console.log();
    console.log("===================== Secp256k1CryptoSuite sign/verify Testing");
    const signature = await suite.getSigners().ES256K.sign(message, ecPrivateKey);
    console.log("Signature : "+Buffer.from(signature, 'base64').toString('hex'));
    console.log("verify : "+ await suite.getSigners().ES256K.verify(message, signature, ecPublicKey));
    console.log();
}

/**
 * JOSE test
 */
async function joseTest() {
    const senderEcPrivateKey = EcPrivateKey.from('did:meta:0x00035#0x1b9b87079', privateKeyHex, 'hex');
    const senderEcPublicKey = EcPublicKey.from('did:meta:0x00035#0x1b9b87079', publicKeyHex, 'hex');
    const recipentEcPrivateKey = EcPrivateKey.from('did:meta:0x00035#89543182598432854', privateKeyHex2, 'hex');
    const recipentEcPublicKey = EcPublicKey.from('did:meta:0x00035#89543182598432854', publicKeyHex2, 'hex');
    const message = 'test message';

    // CryptoFactory 생성. JWE 에서 Symentric encryption 때문에 AES 도 반드시 추가해야 함.
    const hubCryptoSuites = [new ExpandSecp256k1CryptoSuite(), new didAuth.AesCryptoSuite()];
    const cryptoFactory = new didAuth.CryptoFactory(hubCryptoSuites);

    console.log();
    console.log("===================== JOSE Testing     message="+message);

    // Sender....
    // Sender의 private key 로 JWS 생성
    const jwsToken = cryptoFactory.constructJws(message);
    const jwsHeaderParameters = { 'did-requester-nonce': 'test-nonce' };
    // jwsHeaderParameters['alg'] = 'ES256K';
    const jwsCompactString = await jwsToken.sign(senderEcPrivateKey, jwsHeaderParameters);
    console.log('Sending JWS Token : '+jwsCompactString);
    console.log('signature : '+Buffer.from(jwsCompactString.split('.')[2], 'base64').toString('hex'));

    // Recipent의 publick key 로 JWE 생성
    const jweToken = cryptoFactory.constructJwe(jwsCompactString);
    const jwe = await jweToken.encrypt(recipentEcPublicKey);
    console.log('Sending JWE Token : '+jwe.toString());

    // Recipent....
    // Sender 의 public key 로 JWE 에서 JWS 를 얻음
    const jweToken2 = cryptoFactory.constructJwe(jwe.toString());
    const jwsCompactString2 = await jweToken2.decrypt(recipentEcPrivateKey);
    console.log('Receiving JWS Token : '+jwsCompactString2);

    // Recipent 의 private key 로 JWS 에서 메세제를 얻음
    const jwsToken2 = cryptoFactory.constructJws(jwsCompactString2);
    console.log(jwsToken2.getHeader());
    const plaintext = await jwsToken2.verifySignature(senderEcPublicKey);
    console.log('Receiving message : '+plaintext);


    // nimbus-jose 에서 생성한 JSW Verify
    const javaJwsString = 'eyJhbGciOiJFUzI1NksiLCJkaWQtcmVxdWVzdGVyLW5vbmNlIjoidGVzdC1ub25jZSIsImtpZCI6ImRpZDptZXRhOjB4MDAwMzUjMHgxYjliODcwNzkifQ.dGVzdCBtZXNzYWdl.OALMoVyC3cMoFrQQFpiayw17hDKoubCHITAno5ujsqUnv-Xc698Vjs41wXTGzBiSuxmbBEl3r6PIdEXbc4jjEQ';
    const javaJwsToken = cryptoFactory.constructJws(javaJwsString);
    const javaPlainText = await javaJwsToken.verifySignature(senderEcPublicKey);
    console.log('JavaJWS verify : '+javaPlainText);
}

async function joseTestFromJava() {
    const publicKey = EcPublicKey.from('did:meta:0x00035#0x1b9b87079', '0484b9dcfa959dfb3b466f30167465eac7ccce1ce1bbb3b31684d4d4712dd1378fa51012a3fb06d300e84c16efd18e927e508e418d4efc33f93f086d9d3f9179d9', 'hex');

    // CryptoFactory 생성
    const hubCryptoSuites = [new ExpandSecp256k1CryptoSuite(), new didAuth.AesCryptoSuite()];
    const cryptoFactory = new didAuth.CryptoFactory(hubCryptoSuites);

    console.log();
    console.log("===================== JOSE Testing from Java");

    // JWS Verify
    const jws = cryptoFactory.constructJws('eyJraWQiOiJkaWQ6bWV0YTowMDAwMDM0ODkzODQ5MzI4NTk0MjAjS2V5TWFuYWdlbWVudCM3Mzg3NTg5MjQ3NSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTc0OTMwNzc3LCJpYXQiOjE1NjYyOTA3NzcsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.c_vheDncl9lP2ewqocNib7NbqSpr3YpIBmqkL4yrN24FkEgyLy-NkYngcWFewGOSQZv46fAbKahIGd-SmHweZg');
    console.log(jws.getHeader());
    const plaintext = await jws.verifySignature(publicKey);
    console.log('Receiving message : '+plaintext);

    // VC Verify
    const publickey2 = EcPublicKey.from('did:met:d4334', '04b4143b4ea7242687963a804eda9b9b6a16b68e84e23aeeaf0cbde3dfff93239cb8d096654f30c8ea1721b0b86eb058407e21a3897fdd89a7457027559d29e884', 'hex');
    const vp = cryptoFactory.constructJws('eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAjTWFuYWdlbWVudEtleSM0MzgyNzU4Mjk1IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJpc3MiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczpcL1wvdzNpZC5vcmdcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJUZXN0UHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd01EQXdNRE0wT0Rrek9EUTVNekk0TlRrME1qQWpTMlY1VFdGdVlXZGxiV1Z1ZENNM016ZzNOVGc1TWpRM05TSXNJblI1Y0NJNklrcFhWQ0lzSW1Gc1p5STZJa1ZUTWpVMlN5SjkuZXlKemRXSWlPaUprYVdRNmJXVjBZVG93ZURFeE1URXhNVEV4TVRJd0lpd2lhWE56SWpvaVpHbGtPbTFsZEdFNk1IZ3pORGc1TXpnME9UTXlPRFU1TkRJd0lpd2laWGh3SWpveE5UYzBPVE13TnpNMkxDSnBZWFFpT2pFMU5qWXlPVEEzTXpZc0ltNXZibU5sSWpvaU1HUTRiV1l3TXlJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNNMmxrTG05eVoxd3ZZM0psWkdWdWRHbGhiSE5jTDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKT1lXMWxRM0psWkdWdWRHbGhiQ0pkTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnVZVzFsSWpvaWJXRnVjM1ZrSW4xOUxDSnFkR2tpT2lKb2RIUndPbHd2WEM5aFlTNXRaWFJoWkdsMWJTNWpiMjFjTDJOeVpXUmxiblJwWVd4Y0x6TTBNeUo5Lnh2UzJzWk11SXJJZ0g3Rm1DYVVmbk51V3hUeW9YeFJUTFpwdjZNU0toNUxFUFV4M190RnZhOVVtZ2JrQ2xqQzctUloxY2NVUnpfRjJfeGM3UXBrdUZnIiwiZXlKcmFXUWlPaUprYVdRNmJXVjBZVG93TURBd01ETTBPRGt6T0RRNU16STROVGswTWpBalMyVjVUV0Z1WVdkbGJXVnVkQ00zTXpnM05UZzVNalEzTlNJc0luUjVjQ0k2SWtwWFZDSXNJbUZzWnlJNklrVlRNalUyU3lKOS5leUp6ZFdJaU9pSmthV1E2YldWMFlUb3dlREV4TVRFeE1URXhNVEl3SWl3aWFYTnpJam9pWkdsa09tMWxkR0U2TUhnek5EZzVNemcwT1RNeU9EVTVOREl3SWl3aVpYaHdJam94TlRjME9UTXdOelUzTENKcFlYUWlPakUxTmpZeU9UQTNOVGNzSW01dmJtTmxJam9pTUdRNGJXWXdNeUlzSW5aaklqcDdJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPbHd2WEM5M00ybGtMbTl5WjF3dlkzSmxaR1Z1ZEdsaGJITmNMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pPWVcxbFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKdVlXMWxJam9pYldGdWMzVmtJbjE5TENKcWRHa2lPaUpvZEhSd09sd3ZYQzloWVM1dFpYUmhaR2wxYlM1amIyMWNMMk55WldSbGJuUnBZV3hjTHpNME15SjkuSmtsU1hNMkJvT25kOTN0d3B5WEpuZkpZUmI4Vm1NU1FMNWtkNWNDS0RWdWYxdjNtU2NOeUQwRVhuZ25GX3pRT1dlVjItS2V3VHBQeURXcmhxUmwxTHciXX0sIm5vbmNlIjoiMGQ4bWYwMyIsImp0aSI6Imh0dHA6XC9cL2FhLm1ldGFkaXVtLmNvbVwvcHJlc2VudGF0aW9uXC8zNDMifQ.FW_nEPTRg18D2zaX3ACh1atqlJ1alPMGmNzalmUdloo_bG-DevmkcpMm5yPoKB0uaL_oQLYHb6xvFNNwCRSXig');
    const vpJson = await vp.verifySignature(publickey2);
    console.log('VP = '+vpJson);
}


async function joseRSATest() {
    const senderEcPrivateKey = Buffer.from(privateKeyHex, 'hex');
    const senderEcPublicKey = EcPublicKey.from('did:meta:0x00035#0x1b9b87079', publicKeyHex, 'hex');
    const recipentEcPrivateKey = Buffer.from(privateKeyHex2, 'hex');
    const recipentEcPublicKey = EcPublicKey.from('did:meta:0x00035#89543182598432854', publicKeyHex2, 'hex');
}

function RSAKeyTest(eckey) {
    const rsaPublicExponent = '10001';
    const rsaPublicModulus = '8fd511f5d3e24817ca0aa4df77bc6e367c2a878d4d2406399947408a6788367121fe002721f69d3cdedaddb7a9816d8e58047e3f9f7fafc726e6fa9f8bdb7f80ac6cc6ece3fe1ea579784491abeab13ff6a782edc782deb926cd4513b1dbd9b9bc63e79791b120a21b15db7b24a95a37949903ff78e1d5d081b0fa84f5fbe46e646938d9339709763a0043431d2a182adffa9fee25e2205a265ab18cd14a24ed8a7d018af3f3b3d9f68fc7c3dcce12f7848fb4236081851b8cc16c96015f99816f675181adf3d6e0ac6325851fbada2fe55031c4868567d264ff9af0f02de98d5d820ab822869fa342e0027f28aee067e5662dff4dd7c836d8398ec3d562aa41';
    const signature = '1fd89be573f16fe04c3df6f6cefd686574260312d5726b35260d4a62afaa9c722e9b0ba60b706a3b54e42a0488c1de8364ad2ee308dea62ee35e8b91c71c0917e84f2dbddf92cea226e5daacbbc38db5bfa56093d707932cfeb001514f04fd754546d12db3bbf6e100b24476e49471c36f7a09b72b786415bc660b787de30e34a5276744a0823accf4336b2c8129be139c3cc3071aedc559cdeef67e0737878d2e5987b2c4c8e4ca5cfb6ae64d6f4c99f26ec934873554a928dca73b2a8811eda0de5209df6a857b1db9af00ed059ce61299ff02f99bfbe48e2f526d0ed9953ee162553448ea913bd6866d900c24104d8246ab0655a511be111b6164609b1253';

    var publicPem = getPem(Buffer.from(rsaPublicModulus, 'hex').toString('base64'), Buffer.from(rsaPublicExponent, 'hex').toString('base64'));
    console.log("PEM : "+publicPem);

    var publicJwk = pem2jwk(publicPem);
    console.log('jwk');
    publicJwk.defaultEncryptionAlgorithm = 'RSA-OAEP';
    publicJwk.defaultSignAlgorithm = 'RS256',
    publicJwk.kid = 'aaaa'
    console.log(publicJwk);

    var rsaPublicJwk = didAuth.PrivateKeyRsa.wrapJwk(publicJwk.kid, publicJwk);
    console.log(rsaPublicJwk);
    
    var suite = new didAuth.RsaCryptoSuite();
    var verified = suite.getSigners().RS256.verify(Buffer.from(signature, 'hex').toString('base64'), publicJwk);
    console.log("Verified : "+verified);

}

function ecdhesTest() {
    var ecdh = require('ecdh-es')({
        curve_name: 'secp256k1',
        cipher_algo: 'AES-256-CBC',
        key_size: 32,
        iv_size: 16
      });



    const pubkey = new Buffer('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd', 'hex')
    const privkey = new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex')
    
    var encrypted = ecdh.encrypt(pubkey, 'Hello, world!') // -> Buffer

    console.log(encrypted.toString('hex'));

    var decrypted = ecdh.decrypt(privkey, encrypted) // -> Buffer

    console.log(decrypted.toString())

  // (use toString() to convert back to string message)
  
  // Uses the secp256k1 curve and AES-128-CBC cipher by default,
  // but can be overridden as follows:
}

async function nodeJoseTest() {

    const senderEcPrivateKey = EcPrivateKey.from('did:meta:0x00035#0x1b9b87079', privateKeyHex, 'hex');
    const senderEcPublicKey = EcPublicKey.from('did:meta:0x00035#0x1b9b87079', publicKeyHex, 'hex');


    const { JWE, JWK } = require('node-jose');

     // create a private EC key
    // const priv = await JWK.createKey('EC', 'P-256K');

    // simulate only having access to the public key, usually this is your starting point as you only have access to the public components if you're encrypting a message for someone else.
    // const pub = await JWK.asKey(priv.toJSON());

    const encrypted = await JWE.createEncrypt({
        format: 'compact',
        fields: {
        alg: 'ECDH-ES',
        enc: 'A128CBC-HS256',
        cty: 'json', // replace with JWT if you're encrypting a JWT...
        },
    }, {
        key: senderEcPublicKey,
    }).update(JSON.stringify({ foo: 'bar' })).final()

    console.log('encrypted', encrypted);


    // // now we decrypt using the private key
    //   const decrypted = await JWE.createDecrypt(senderEcPrivateKey).decrypt(encrypted);
    // console.log('decrypted', JSON.parse(decrypted.payload.toString('utf8')));
}

async function test() {

    // KeyTest();

    // await Secp256k1CryptoSutieTest();


    // await joseTest();

    await joseTestFromJava();

    // RSAKeyTest();

    // ecdhesTest();

    // await nodeJoseTest();

}


test();







