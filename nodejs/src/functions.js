const crypto = require('crypto')

module.exports = {
    generateRandomBytes: function (length) {
        return crypto.randomBytes(length).toString('base64')
    },

    generateSessionKey: function (sessionId, secretKey, iv, base64PublicKey) {
        let sessionAesKey = 'AES_GCM$' + secretKey + '$' + iv
        let encryptedSessionAesKey = this.encryptSessionAesKey(base64PublicKey, sessionAesKey)
        return 'v1$' + sessionId + '$' + encryptedSessionAesKey
    },

    encryptSessionAesKey: function (base64PublicKey, sessionAesKey) {
        let encrypted = crypto.publicEncrypt({
            key: '-----BEGIN PUBLIC KEY-----\n' + base64PublicKey + '\n-----END PUBLIC KEY-----',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, Buffer.from(sessionAesKey, 'utf-8'))

        return encrypted.toString('base64')
    },

    encryptData: function (sessionId, secretKey, iv, data) {
        let cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(secretKey, 'base64'), Buffer.from(iv, 'base64'))
        cipher.setAAD(Buffer.from(secretKey, 'base64'))

        let encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()])

        let combined = Buffer.concat([encrypted, cipher.getAuthTag()]).toString('base64')
        return 'v1$' + sessionId + '$' + combined
    },

    decryptData: function (secretKey, iv, encryptedData) {
        let parsed = Buffer.from(encryptedData.split('$')[2], 'base64')
        let encrypted = parsed.slice(0, parsed.length - 16)
        let tag = parsed.slice(parsed.length - 16)

        let cipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(secretKey, 'base64'), Buffer.from(iv, 'base64'))
        cipher.setAAD(Buffer.from(secretKey, 'base64'))
        cipher.setAuthTag(tag)

        let decrypted = Buffer.concat([cipher.update(encrypted), cipher.final()])
        return decrypted.toString('utf-8')
    }
}
