const assert = require('assert')

const f = require('../src/functions')
const t = require('./test_data')
const crypto = require('crypto')

module.exports = {
    testDecryptSessionKey: function () {
        for (let data of t.RSA_TEST_DATA) {
            let secretKey = data[1]
            let iv = data[2]
            let sessionKey = data[3]
            let decryptedSessionKey = this.decryptSessionKey(t.TEST_BASE64_PRIVATE_KEY, sessionKey.split('$')[2])

            console.log(decryptedSessionKey)
            assert.equal('AES_GCM$' + secretKey + '$' + iv, decryptedSessionKey)
        }
    },

    testGenerateSessionKey: function () {
        for (let data of t.RSA_TEST_DATA) {
            let sessionId = data[0]
            let secretKey = data[1]
            let iv = data[2]
            let sessionKey = data[3]
            let generatedSessionKey = f.generateSessionKey(sessionId, secretKey, iv, t.TEST_BASE64_PUBLIC_KEY)
            let decryptedSessionKey = this.decryptSessionKey(t.TEST_BASE64_PRIVATE_KEY, sessionKey.split('$')[2])

            console.log(generatedSessionKey)
            console.log(decryptedSessionKey)

            assert.equal(sessionKey.substring(0, 40), generatedSessionKey.substring(0, 40))
            assert.equal('AES_GCM$' + secretKey + '$' + iv, decryptedSessionKey)
        }
    },

    testEncryptDecryptData: function () {
        for (let data of t.AES_TEST_DATA) {
            let sessionId = data[0]
            let secretKey = data[1]
            let iv = data[2]
            let plain = data[3]
            let encrypted = data[4]

            let encryptedData = f.encryptData(sessionId, secretKey, iv, plain)
            let decryptedData = f.decryptData(secretKey, iv, encrypted)

            console.log(encryptedData)
            console.log(decryptedData)

            assert.equal(encrypted, encryptedData)
            assert.equal(plain, decryptedData)
        }
    },

    decryptSessionKey: function (base64PrivateKey, sessionKey) {
        let decrypted = crypto.privateDecrypt({
            key: '-----BEGIN PRIVATE KEY-----\n' + base64PrivateKey + '\n-----END PRIVATE KEY-----',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(sessionKey, 'base64'))

        return decrypted.toString('utf-8')
    }
}