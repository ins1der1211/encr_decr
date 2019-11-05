package com.example.encryptiondecryption.security_utils.api_above_23

import android.content.Context
import android.util.Base64
import com.example.encryptiondecryption.security_utils.SymmetricKeysHelper
import com.example.encryptiondecryption.security_utils.api_less_24.SecretKeyWrapperOld
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SymmetricKeysHelperOld(ctx: Context): SymmetricKeysHelper {

    private val secretKeyWrapper = SecretKeyWrapperOld(ctx)
    private val prefs = ctx.getSharedPreferences("symmetric_key_helper", Context.MODE_PRIVATE)
    private val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    init {
        generateKeys()
    }

    override fun encryptSymmetric(text: String): String? {
        setProvider()
        val data = text.toByteArray()
        val secureRandom = SecureRandom()
        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, loadKey(), GCMParameterSpec(iv.size * 8, iv))
        val encrypted = cipher.doFinal(data)
        val byteBuffer = ByteBuffer.allocate(4 + iv.size + encrypted.size)
        byteBuffer.putInt(iv.size)
        byteBuffer.put(iv)
        byteBuffer.put(encrypted)
        Arrays.fill(data, 0)
        val buffer = byteBuffer.array()
        removeProvider()
        return Base64.encodeToString(buffer, Base64.DEFAULT)
    }

    override fun digest(text: String): ByteArray {
        val message: ByteArray = text.toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val digest: ByteArray = md.digest(message)
        return digest
    }

    override fun decryptSymmetric(text: String): String? {
        setProvider()
        val data = Base64.decode(text, Base64.DEFAULT)
        val byteBuffer = ByteBuffer.wrap(data)
        val ivLength = byteBuffer.int
        if (ivLength != 12) { // check input parameter
            throw IllegalArgumentException("invalid iv length")
        }
        val iv = ByteArray(ivLength)
        byteBuffer.get(iv)
        val cipherText = ByteArray(byteBuffer.remaining())
        byteBuffer.get(cipherText)
        cipher.init(Cipher.DECRYPT_MODE, loadKey(), GCMParameterSpec(iv.size * 8, iv))
        val decrypted= cipher.doFinal(cipherText)
        removeProvider()
        return String(decrypted)
    }

    private fun generateKeys() {
        if (prefs.getString(SECRET_KEY, null).isNullOrEmpty()) {
            prefs.edit().putString(SECRET_KEY, Base64.encodeToString(secretKeyWrapper.wrap(getSecretKeySpec()), Base64.DEFAULT)).apply()
        }
    }

    private fun loadKey(): SecretKey {
        return secretKeyWrapper.unwrap(Base64.decode(prefs.getString(SECRET_KEY, null)!!, Base64.DEFAULT))
    }

    private fun getSecretKeySpec(): SecretKeySpec {
        val secureRandom = SecureRandom()
        val key = ByteArray(32)
        secureRandom.nextBytes(key)
        return SecretKeySpec(key, "AES")
    }

    private fun setProvider(){
        if (Security.getProvider("SC") == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    private fun removeProvider(){
        if (Security.getProvider("SC") != null) {
            Security.removeProvider("SC")
        }
    }

    companion object {
        private const val SECRET_KEY = "secret_key"
    }
}