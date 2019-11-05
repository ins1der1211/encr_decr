package com.example.encryptiondecryption.security_utils.api_above_23

import android.content.Context
import java.math.BigInteger
import javax.security.auth.x500.X500Principal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.example.encryptiondecryption.security_utils.AsymmetricKeysHelper
import com.example.encryptiondecryption.security_utils.api_less_24.SecretKeyWrapperOld
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec


class AsymmetricKeysHelperOld(ctx: Context): AsymmetricKeysHelper {

    private val secretKeyWrapper = SecretKeyWrapperOld(ctx)
    private val prefs = ctx.getSharedPreferences("asymmetric_key_helper", Context.MODE_PRIVATE)

    private val signature = Signature.getInstance("SHA256withRSA")
    private val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

    init {
        generateKeys()
    }

    private fun generateKeys() {
        if (prefs.getString(SECRET_KEY, null).isNullOrEmpty()) {
            prefs.edit().putString(SECRET_KEY, Base64.encodeToString(secretKeyWrapper.wrap(getSecretKeySpec()), Base64.DEFAULT)).apply()
            createKeysInternal()
        }
    }

    private fun getSecretKeySpec(): SecretKeySpec {
        val secureRandom = SecureRandom()
        val key = ByteArray(32)
        secureRandom.nextBytes(key)
        return SecretKeySpec(key, "AES")
    }

    private val secretKey: SecretKey
        get() = secretKeyWrapper.unwrap(Base64.decode(prefs.getString(SECRET_KEY, null)!!, Base64.DEFAULT))

    private val privateKey: PrivateKey
        get() {
            val decryptedPrivateKey = decryptSymmetric(prefs.getString(PRIVATE_KEY, null)!!)
            return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(decryptedPrivateKey))
        }

    private val publicKey: PublicKey
        get() {
            val decryptedPublicKey = decryptSymmetric(prefs.getString(PUBLIC_KEY, null)!!)
            return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(decryptedPublicKey))
        }

    override fun createKeys() {}

    private fun createKeysInternal() {

        if (!prefs.getString(SECRET_KEY, null).isNullOrEmpty() &&
            !prefs.getString(PRIVATE_KEY, null).isNullOrEmpty() &&
            !prefs.getString(PUBLIC_KEY, null).isNullOrEmpty())
            return

        try {
            setProvider()
            val kpg = KeyPairGenerator.getInstance("RSA", "SC")
            kpg.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            val kp = kpg.generateKeyPair()
            prefs.edit().putString(PUBLIC_KEY, encryptSymmetric(kp.public.encoded)).apply()
            prefs.edit().putString(PRIVATE_KEY, encryptSymmetric(kp.private.encoded)).apply()
        } finally {
            removeProvider()
        }
    }

    private fun encryptSymmetric(keyByteArray: ByteArray): String? {
        setProvider()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secureRandom = SecureRandom()
        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(iv.size * 8, iv))
        val encrypted = cipher.doFinal(keyByteArray)
        val byteBuffer = ByteBuffer.allocate(4 + iv.size + encrypted.size)
        byteBuffer.putInt(iv.size)
        byteBuffer.put(iv)
        byteBuffer.put(encrypted)
        Arrays.fill(keyByteArray, 0)
        val buffer = byteBuffer.array()
        removeProvider()
        return Base64.encodeToString(buffer, Base64.DEFAULT)
    }

    private fun decryptSymmetric(keyBase64Encoded: String): ByteArray {
        val decrypted: ByteArray
        try {
            setProvider()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val data = Base64.decode(keyBase64Encoded, Base64.DEFAULT)
            val byteBuffer = ByteBuffer.wrap(data)
            val ivLength = byteBuffer.int
            if (ivLength != 12) { // check input parameter
                throw IllegalArgumentException("invalid iv length")
            }
            val iv = ByteArray(ivLength)
            byteBuffer.get(iv)
            val cipherText = ByteArray(byteBuffer.remaining())
            byteBuffer.get(cipherText)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(iv.size * 8, iv))
            decrypted = cipher.doFinal(cipherText)
        } finally {
            removeProvider()
        }
        return decrypted
    }

    override fun signData(inputStr: String): String? {
        val s: ByteArray
        try {
            setProvider()
            val data = inputStr.toByteArray()
            val ss = signature
            ss.initSign(privateKey)
            ss.update(data)
            s = ss.sign()
        } finally {
            removeProvider()
        }
        return Base64.encodeToString(s, Base64.DEFAULT)
    }

    override fun verifyData(input: String, signatureStr: String?): Boolean {
        val res: Boolean
        try {
            setProvider()
            val data = input.toByteArray()
            val s: ByteArray

            if (signatureStr == null) {
                Log.w(TAG, "Invalid signature.")
                Log.w(TAG, "Exiting verifyData()...")
                return false
            }

            try {
                s = Base64.decode(signatureStr, Base64.DEFAULT)
            } catch (e: IllegalArgumentException) {
                return false
            }

            val ss = signature
            ss.initVerify(publicKey)
            ss.update(data)
            res = ss.verify(s)
        } finally {
            removeProvider()
        }
        return res
    }

    override fun encryptByPublicKey(inputStr: String): String? {
        val res: String?
        try {
            setProvider()
            val data = inputStr.toByteArray()
            val c = cipher
            c.init(Cipher.ENCRYPT_MODE, publicKey)
            res = Base64.encodeToString(c.doFinal(data), Base64.DEFAULT)
        } finally {
            removeProvider()
        }
        return res
    }

    override fun decryptByPrivateKey(inputStr: String): String? {
        val res: String
        try {
            setProvider()
            val data = Base64.decode(inputStr, Base64.DEFAULT)
            val c = cipher
            c.init(Cipher.DECRYPT_MODE, privateKey)
            res = String(c.doFinal(data))
        } finally {
            removeProvider()
        }
        return res
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

    override fun deleteKeys() {
        prefs.edit().remove(SECRET_KEY).apply()
        prefs.edit().remove(PRIVATE_KEY).apply()
        prefs.edit().remove(PUBLIC_KEY).apply()
        generateKeys()
    }

    companion object {
        val TAG = "AsymmetricKeysHelperOld"
        private const val SECRET_KEY = "secret_key"
        private const val PUBLIC_KEY = "public_key"
        private const val PRIVATE_KEY = "private_key"
    }

}