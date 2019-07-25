const Secp256k1CryptoSuite = require('./ExpandSecp256k1CryptoSuite')
const didAuth = require('@decentralized-identity/did-auth-jose');
const EcPublicKey = require('./ExpandEcPublicKey');
const EcPrivateKey = require('./ExpandEcPrivateKey');

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
    var suite = new Secp256k1CryptoSuite();
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
    const hubCryptoSuites = [new Secp256k1CryptoSuite(), new didAuth.AesCryptoSuite()];
    const cryptoFactory = new didAuth.CryptoFactory(hubCryptoSuites);

    console.log('message : '+message);

    // Sender....
    // Sender의 private key 로 JWS 생성
    const jwsToken = cryptoFactory.constructJws(message);
    const jwsHeaderParameters = { 'did-requester-nonce': 'test-nonce' };
    // jwsHeaderParameters['alg'] = 'ES256K';
    const jwsCompactString = await jwsToken.sign(senderEcPrivateKey, jwsHeaderParameters);
    console.log('Sending JWS Token : '+jwsCompactString);

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
    const plaintext = await jwsToken2.verifySignature(senderEcPublicKey);
    console.log('Receiving message : '+plaintext);
    
}

async function test() {

    KeyTest();

    await Secp256k1CryptoSutieTest();


    await joseTest();

}


test();







