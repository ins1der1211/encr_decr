package com.example.encryptiondecryption.security_utils.api_above_23

import android.content.Context
import android.util.Base64
import androidx.annotation.RequiresApi
import com.example.encryptiondecryption.security_utils.SecretKeyWrapperHelper
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@RequiresApi(24)
class SecretKeyWrapperHelperNew(ctx: Context): SecretKeyWrapperHelper {

    val secretKeyWrapper = SecretKeyWrapperNew()
    private val prefs = ctx.getSharedPreferences("appsigner", Context.MODE_PRIVATE)

    private val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    init {
        saveKey()
    }

    private fun getSecretKeySpec(): SecretKeySpec {
        val secureRandom = SecureRandom()
        val key = ByteArray(16)
        secureRandom.nextBytes(key)
        return SecretKeySpec(key, "AES")
    }

    private fun saveKey() {
        val secretKeyWrapped  = secretKeyWrapper.wrap(getSecretKeySpec())
        prefs.edit().putString(SECRET_KEY, Base64.encodeToString(secretKeyWrapped, Base64.DEFAULT)).apply()
    }

    private fun loadKey(): SecretKey {
        return secretKeyWrapper.unwrap(Base64.decode(prefs.getString(SECRET_KEY, null), Base64.DEFAULT))
    }

    override fun encryptWithWrappedKey(text: String): String? {
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
        return Base64.encodeToString(buffer, Base64.DEFAULT)
    }

    override fun decryptWithWrappedKey(text: String): String? {
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
        return String(cipher.doFinal(cipherText))
    }

    companion object {
        private const val SECRET_KEY = "secret_key"
    }

}