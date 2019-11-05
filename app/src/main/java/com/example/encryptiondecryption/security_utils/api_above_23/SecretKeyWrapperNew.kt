package com.example.encryptiondecryption.security_utils.api_above_23

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.example.encryptiondecryption.security_utils.SecretKeyWrapper
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

@RequiresApi(24)
class SecretKeyWrapperNew: SecretKeyWrapper {

    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

    private val keyPair: KeyStore.PrivateKeyEntry?
        get() = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry?

    companion object {
        private const val alias = "key_wrapper"
    }

    init {
        createKeys()
    }

    private fun createKeys() {

        if (ks.containsAlias(alias)) return

        val kpGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore"
        )
        kpGenerator.initialize(getRSAParameterSpec())
        kpGenerator.generateKeyPair()
    }

    private fun getRSAParameterSpec(): KeyGenParameterSpec {
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 1)
        val spec = KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setCertificateSubject(X500Principal("CN=" + alias))
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

    override fun wrap(key: SecretKey): ByteArray {
        cipher.init(Cipher.WRAP_MODE, keyPair!!.certificate.publicKey)
        return cipher.wrap(key)
    }

    override fun unwrap(blob: ByteArray): SecretKey {
        cipher.init(Cipher.UNWRAP_MODE, keyPair!!.privateKey)
        return cipher.unwrap(blob, "AES", Cipher.SECRET_KEY) as SecretKey
    }

}