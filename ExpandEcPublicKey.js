const PublicKey_1 = require('@decentralized-identity/did-auth-jose/dist/lib/security/PublicKey');
const ecKey = require('ec-key');;

/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class ExpandEcPublicKey extends PublicKey_1.default {
    constructor(keyData) {
        super();
        this.kty = PublicKey_1.RecommendedKeyType.Ec;
        this.kid = keyData.id;

        // set encryption algorithm
        this.defaultEncryptionAlgorithm = 'ECIES';

        const data = keyData;
        if ('publicKeyJwk' in data) {
            const jwk = data.publicKeyJwk;
            if (!keyData.id.endsWith(jwk.kid)) {
                throw new Error('JWK kid does not match Did publickey id.');
            }
            if (!jwk.crv || !jwk.x || !jwk.y) {
                throw new Error('JWK missing required parameters.');
            }
            this.crv = jwk.crv;
            this.x = jwk.x;
            this.y = jwk.y;
            this.key_ops = jwk.key_ops;
            this.use = this.use;
        }
        // add to parse publickey hex
        else if ('publicKeyHex' in data) {
            var jwk = ExpandEcPublicKey.publicKeyToJwk(this.kid, keyData.publicKeyHex, 'hex');

            if (!jwk.crv || !jwk.x || !jwk.y) {
                throw new Error('JWK missing required parameters.');
            }
            this.crv = jwk.crv;
            this.x = jwk.x;
            this.y = jwk.y;
            this.key_ops = jwk.key_ops;
            this.use = this.use;
        }
        else {
            throw new Error('Cannot parse Elliptic Curve key.');
        }
    }

    /**
     * Wraps a EC public key in jwk format into a Did Document public key object with additonal information
     * @param {string} kid Key ID
     * @param {object} jwk JWK of the public key
     */
    static wrapJwk(kid, jwk) {
        return new ExpandEcPublicKey({
            id: kid,
            type: 'EdDsaSAPublicKeySecp256k1',
            publicKeyJwk: jwk
        });
    }

    /**
     * Convert encoded public key to jwk
     * @param {string} kid Key ID
     * @param {string} publicKey string encoded public key
     * @param {string} fromEncoding encoding format of publicKey. 'hex', 'base64', ...
     */
    static publicKeyToJwk(kid, publicKey, fromEncoding) {
        var key = new ecKey({
            publicKey: Buffer.from(publicKey, fromEncoding),
            curve: 'secp256k1'
        });

        var jwk = Object.assign(key.toJSON(), {
            kid: kid,
            alg: 'ES256K',
            key_ops: ['Verify'],
            defaultEncryptionAlgorithm: 'ECIES'
        });

        return jwk;
    }

    /**
     * Create Did Document public key object with encoded public key
     * @param {string} kid Key ID
     * @param {string} publicKey encoded public key
     * @param {string} fromEncoding encoding format of publicKey. 'hex', 'base64', ...
     */
    static from(kid, publicKey, fromEncoding) {
        return ExpandEcPublicKey.wrapJwk(kid, ExpandEcPublicKey.publicKeyToJwk(kid, publicKey, fromEncoding));
    }

    /**
     * Get encoded public key
     * @param {string} encoding encoding format of publicKey. 'hex', 'base64', ...
     */
    toPublicKey(encoding) {
        return Buffer.concat([ Buffer.from([0x04]), Buffer.from(this.x, 'base64'), Buffer.from(this.y, 'base64')]).toString(encoding);
    }
}

module.exports = ExpandEcPublicKey;