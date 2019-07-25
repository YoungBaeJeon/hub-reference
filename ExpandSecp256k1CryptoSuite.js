const didAuth = require('@decentralized-identity/did-auth-jose');
const ecies = require('bitcore-ecies');
const ecKey = require('ec-key');
const bitcore = require('bitcore-lib');
const secp256k1 = require('secp256k1');
const keccak256 = require('keccak256');

var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;

var EcPublicKey = require('./ExpandEcPublicKey')

class ExpandSecp256k1CryptoSuite extends didAuth.Secp256k1CryptoSuite
{
    getEncrypters() {
        return {
            'ECIES': {
                encrypt: ExpandSecp256k1CryptoSuite.encrypt,
                decrypt: ExpandSecp256k1CryptoSuite.decrypt
            }
        };
    }

    getKeyConstructors() {
        return {
            Secp256k1VerificationKey2018: (keyData) => { return new EcPublicKey(keyData); },
            EdDsaSAPublicKeySecp256k1: (keyData) => { return new EcPublicKey(keyData); },
            EdDsaSASignatureSecp256k1: (keyData) => { return new EcPublicKey(keyData); },
            EcdsaPublicKeySecp256k1: (keyData) => { return new EcPublicKey(keyData); }
        };
    }

    getSigners() {
        return {
            ES256K: {
                sign: ExpandSecp256k1CryptoSuite.sign,
                verify: ExpandSecp256k1CryptoSuite.verify
            }
        };
    }

    static encrypt(data, jwk) {
        return new Promise((resolve) => {
            const publicKey = Buffer.concat([ Buffer.from([0x04]), Buffer.from(jwk.x, 'base64'), Buffer.from(jwk.y, 'base64')]);
            const key = ecKey.createECKey('secp256k1');

            var ecdhkeySender = key.createECDH("secp256k1");
            ecdhkeySender.generateKeys();

            var pri = new PrivateKey(ecdhkeySender.getPrivateKey());
            var pub = new PublicKey(publicKey);
            var eciesCipher = ecies().privateKey(pri).publicKey(pub);
            
            const encryptedDataBuffer = eciesCipher.encrypt(data);
            resolve(encryptedDataBuffer);
        });
    }


    static decrypt(data, jwk) {
        return new Promise((resolve) => {
            const key = new ecKey(jwk);
            var ecdhkey = key.createECDH("secp256k1");
            const decryptedDataBuffer = ecies().privateKey(new PrivateKey(ecdhkey.getPrivateKey())).decrypt(data);
            resolve(decryptedDataBuffer);
        });
    }

    /**
     * Verifies the given signed content using SHA256 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verify(signedContent, signature, jwk) {
        return new Promise((resolve) => {
            const signatureBuffer = Buffer.from(signature, 'base64');
            const publicKey = Buffer.concat([ Buffer.from([0x04]), Buffer.from(jwk.x, 'base64'), Buffer.from(jwk.y, 'base64')]);
            const verify = secp256k1.verify(keccak256(Buffer.from(signedContent)), signatureBuffer.slice(0, signatureBuffer.length-1), publicKey);
            resolve(verify);
        });
    }
    /**
     * Sign the given content using the given private key in JWK format using algorithm SHA256.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static sign(content, jwk) {
        return new Promise((resolve) => {
            const eckey = new ecKey(jwk).createECDH('secp256k1');
            const signObj = secp256k1.sign(keccak256(Buffer.from(content)), eckey.getPrivateKey());
            const signature = Buffer.concat([signObj.signature, Buffer.from([signObj.recovery+27])]).toString('base64');
            resolve(signature);
        });
    }
}

module.exports = ExpandSecp256k1CryptoSuite;