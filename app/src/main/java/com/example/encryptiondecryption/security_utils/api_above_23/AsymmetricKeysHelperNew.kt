package com.example.encryptiondecryption.security_utils.api_above_23

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Calendar
import java.util.GregorianCalendar
import javax.security.auth.x500.X500Principal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.encryptiondecryption.security_utils.AsymmetricKeysHelper
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher

@RequiresApi(24)
class AsymmetricKeysHelperNew: AsymmetricKeysHelper {

    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val signature: Signature
        get() {
            return when (keyAlgorithm) {
                KeyProperties.KEY_ALGORITHM_RSA -> Signature.getInstance("SHA256withRSA")
                KeyProperties.KEY_ALGORITHM_EC -> Signature.getInstance("SHA256withECDSA")
                else -> throw Exception("Only EC and RSA algorithms supported")
            }
        }

    private val cipher: Cipher
        get() {
            return when(keyAlgorithm) {
                KeyProperties.KEY_ALGORITHM_RSA -> Cipher.getInstance("RSA/ECB/PKCS1Padding")
                KeyProperties.KEY_ALGORITHM_EC -> throw Exception("Can't encrypt/decrypt with EC key")
                else -> throw Exception("Only EC and RSA algorithms supported")
            }
        }

    private val keyPair: KeyStore.PrivateKeyEntry?
        get() = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry?

    var alias: String? = null
    var keyAlgorithm: String = KeyProperties.KEY_ALGORITHM_EC

    override fun createKeys() {

        if (keyPair?.privateKey?.algorithm == keyAlgorithm) return
        else deleteKeys()

        val kpGenerator = KeyPairGenerator.getInstance(
            keyAlgorithm,
            "AndroidKeyStore"
        )
        kpGenerator.initialize(getKeyGenParameterSpec())
        val kp = kpGenerator.generateKeyPair()
        Log.d(TAG, "Public Key is: " + kp.public.toString())

    }

    override fun signData(inputStr: String): String? {
        val data = inputStr.toByteArray()

        val entry = keyPair!!

        val ss = signature
        ss.initSign(entry.privateKey)
        ss.update(data)
        val s = ss.sign()

        return Base64.encodeToString(s, Base64.DEFAULT)
    }

    override fun verifyData(input: String, signatureStr: String?): Boolean {
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

        val entry = keyPair!!

        val ss = signature
        ss.initVerify(entry.certificate)
        ss.update(data)
        return ss.verify(s)

    }

    override fun encryptByPublicKey(inputStr: String): String? {
        val data = inputStr.toByteArray()
        val c = cipher
        val entry = keyPair!!

        c.init(Cipher.ENCRYPT_MODE, entry.certificate.publicKey)
        return Base64.encodeToString(c.doFinal(data), Base64.DEFAULT)
    }

    override fun decryptByPrivateKey(inputStr: String): String? {
        val data = Base64.decode(inputStr, Base64.DEFAULT)
        val c = cipher
        val entry = keyPair!!

        c.init(Cipher.DECRYPT_MODE, entry.privateKey)
        return String(c.doFinal(data))
    }

    private fun getKeyGenParameterSpec(): KeyGenParameterSpec {
        return when (keyAlgorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> getECParameterSpec()
            KeyProperties.KEY_ALGORITHM_RSA -> getRSAParameterSpec()
            else -> throw Exception("Only EC and RSA algorithms supported")
        }
    }

    private fun getECParameterSpec(): KeyGenParameterSpec {
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 1)
        val spec = KeyGenParameterSpec.Builder(
            alias!!,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setCertificateSubject(X500Principal("CN=" + alias!!))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setCertificateNotBefore(start.time)
            .setCertificateNotAfter(end.time)
            .setKeyValidityStart(start.time)
            .setKeyValidityEnd(end.time)
            .setCertificateSerialNumber(BigInteger.valueOf(1))
//            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp224r1"))
//            .setAlgorithmParameterSpec(ECGenParameterSpec("secp384r1"))
//            .setAlgorithmParameterSpec(ECGenParameterSpec("secp521r1"))
            .build()
        return spec
    }

    private fun getRSAParameterSpec(): KeyGenParameterSpec {
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 1)
        val spec = KeyGenParameterSpec.Builder(
            alias!!,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setCertificateSubject(X500Principal("CN=" + alias!!))
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setCertificateNotBefore(start.time)
            .setCertificateNotAfter(end.time)
            .setKeyValidityStart(start.time)
            .setKeyValidityEnd(end.time)
            .setKeySize(2048)
            .setCertificateSerialNumber(BigInteger.valueOf(1))
            .build()
        return spec
    }

//    private fun oldKeyGenSpec(context: Context): KeyPairGeneratorSpec {
//        val start = GregorianCalendar()
//        val end = GregorianCalendar()
//        end.add(Calendar.YEAR, 1)
//        val spec = KeyPairGeneratorSpec.Builder(context)
//            .setAlias(alias!!)
//            .setSubject(X500Principal("CN=$alias"))
//            .setSerialNumber(BigInteger.valueOf(1337))
//            .setStartDate(start.time).setEndDate(end.time)
//            .build()
//        return spec
//    }

    override fun deleteKeys() {
        ks.deleteEntry(alias)
    }

    companion object {
        val TAG = "AsymmetricKeysHelperNew"
    }

}