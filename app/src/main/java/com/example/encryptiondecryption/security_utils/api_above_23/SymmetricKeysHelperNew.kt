package com.example.encryptiondecryption.security_utils.api_above_23

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import com.example.encryptiondecryption.security_utils.SymmetricKeysHelper
import java.nio.ByteBuffer
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

@RequiresApi(24)
class SymmetricKeysHelperNew(var alias: String): SymmetricKeysHelper {

    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    private val cipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    init {
        initSecretKey()
    }

    private fun initSecretKey() {
        val keygen = KeyGenerator.getInstance("AES")
        keygen.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .setKeySize(256)
            .build())
        keygen.generateKey()
    }

    override fun encryptSymmetric(text: String): String? {
        val data = text.toByteArray()
        val secureRandom = SecureRandom()
        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, ks.getKey(alias, null), GCMParameterSpec(iv.size * 8, iv))
        val encrypted = cipher.doFinal(data)
        val byteBuffer = ByteBuffer.allocate(4 + iv.size + encrypted.size)
        byteBuffer.putInt(iv.size)
        byteBuffer.put(iv)
        byteBuffer.put(encrypted)
        Arrays.fill(data, 0)
        val buffer = byteBuffer.array()
        return Base64.encodeToString(buffer, Base64.DEFAULT)
    }

    override fun digest(text: String): ByteArray {
        val message: ByteArray = text.toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val digest: ByteArray = md.digest(message)
        return digest
    }

    override fun decryptSymmetric(text: String): String? {
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
        cipher.init(Cipher.DECRYPT_MODE, ks.getKey(alias, null), GCMParameterSpec(iv.size * 8, iv))
        return String(cipher.doFinal(cipherText))
    }

//    private fun oldKeyGenSpec(context: Context): KeyPairGeneratorSpec {
//        val start = GregorianCalendar()
//        val end = GregorianCalendar()
//        end.add(Calendar.YEAR, 1)
//        val spec = KeyPairGeneratorSpec.Builder(context)
//            .setAlias(alias)
//            .setSubject(X500Principal("CN=${alias}"))
//            .setSerialNumber(BigInteger.valueOf(1337))
//            .setStartDate(start.time).setEndDate(end.time)
//            .build()
//        return spec
//    }
}