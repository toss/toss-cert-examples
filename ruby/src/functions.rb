require 'base64'
require 'openssl'
require 'securerandom'

def generate_session_id
  SecureRandom.uuid
end

def generate_random_bytes(length)
  Base64.strict_encode64(SecureRandom.random_bytes(length))
end

def generate_session_key(session_id, secret_key, iv, base64_public_key)
  session_aes_key = 'AES_GCM$' + secret_key + '$' + iv
  encrypted_session_aes_key = encrypt_session_aes_key(base64_public_key, session_aes_key)
  'v1$' + session_id + '$' + encrypted_session_aes_key
end

def encrypt_session_aes_key(base64_public_key, session_aes_key)
  public_key = OpenSSL::PKey::RSA.new(Base64.strict_decode64(base64_public_key))

  encrypted = public_key.public_encrypt(session_aes_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  Base64.strict_encode64(encrypted)
end

def encrypt_data(session_id, secret_key, iv, data)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = Base64.strict_decode64(secret_key)
  cipher.iv = Base64.strict_decode64(iv)
  cipher.auth_data = Base64.strict_decode64(secret_key)

  encrypted = cipher.update(data) + cipher.final
  combined = Base64.strict_encode64(encrypted + cipher.auth_tag)
  'v1$' + session_id + '$' + combined
end

def decrypt_data(secret_key, iv, encrypted_data)
  parsed = Base64.strict_decode64(encrypted_data.split('$')[2])
  encrypted = parsed[0..-17]
  tag = parsed[-16..-1]

  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = Base64.strict_decode64(secret_key)
  cipher.iv = Base64.strict_decode64(iv)
  cipher.auth_data = Base64.strict_decode64(secret_key)
  cipher.auth_tag = tag

  decrypted = cipher.update(encrypted) + cipher.final
  decrypted.force_encoding('UTF-8')
end