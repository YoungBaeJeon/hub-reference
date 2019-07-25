const ExpandEcPublicKey = require('./ExpandEcPublicKey');
const crypto = require('crypto');
const ecKey = require('ec-key');;

/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class ExpandEcPrivateKey extends ExpandEcPublicKey {
    /**
     * Constructs a private key given a DID Document public key descriptor containing additional private key
     * information.
     *
     * TODO: This feels odd, should define a separate type.
     *
     * @param key public key object with additional private key information
     */
    constructor(key) {
        super(key);
        /** ECDSA w/ secp256k1 Curve */
        this.defaultSignAlgorithm = 'ES256K';
        let data = key.publicKeyJwk;
        if (!('d' in data)) {
            throw new Error('d required for private elliptic curve key.');
        }
        this.d = data.d;
    }
    /**
     * Wraps a EC private key in jwk format into a Did Document public key object with additonal information
     * @param kid Key ID
     * @param jwk JWK of the private key
     */
    static wrapJwk(kid, jwk) {
        return new ExpandEcPrivateKey({
            id: kid,
            type: 'EdDsaSAPublicKeySecp256k1',
            publicKeyJwk: jwk
        });
    }
    /**
     * Generates a new private key
     * @param kid Key ID
     */
    static generatePrivateKey(kid) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = ecKey.createECKey('P-256K');
            // Add the additional JWK parameters
            const jwk = Object.assign(key.toJSON(), {
                kid: kid,
                alg: 'ES256K',
                key_ops: [PublicKey_1.KeyOperation.Sign, PublicKey_1.KeyOperation.Verify]
            });
            return ExpandEcPrivateKey.wrapJwk(kid, jwk);
        });
    }

    /**
     * Create Did Document private key object with encoded private key
     * @param {string} kid Key ID
     * @param {string} privateKey encoded private key
     * @param {string} encoding encoding format of privateKey. 'hex', 'base64', ...
     */
    static from(kid, privateKey, encoding) {
        var ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(Buffer.from(privateKey, encoding));

        var key = new ecKey({
            privateKey: ecdh.getPrivateKey(),
            publicKey: ecdh.getPublicKey(),
            curve: 'secp256k1'
        });

        var jwk = Object.assign(key.toJSON(), {
            kid: kid,
            alg: 'ES256K',
            key_ops: ['sign', 'verify']
        });

        return ExpandEcPrivateKey.wrapJwk(kid, jwk);
    }

    /**
     * Get encoded private key
     * @param {string} encoding encoding format of privateKey. 'hex', 'base64', ...
     */
    toPrivateKey(encoding) {
        const key = new ecKey(this);
        var ecdhkey = key.createECDH("seck256k1");
        return ecdhkey.getPrivateKey().toString(encoding);
    }

    getPublicKey() {
        return {
            kty: this.kty,
            kid: this.kid,
            crv: this.crv,
            x: this.x,
            y: this.y,
            use: 'verify',
            defaultEncryptionAlgorithm: 'none'
        };
    }
}

module.exports = ExpandEcPrivateKey;