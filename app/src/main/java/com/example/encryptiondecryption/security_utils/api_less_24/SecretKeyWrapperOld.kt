package com.example.encryptiondecryption.security_utils.api_less_24

import android.content.Context
import android.security.KeyPairGeneratorSpec
import org.spongycastle.asn1.x500.X500NameBuilder
import org.spongycastle.asn1.x500.style.BCStyle
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.cert.X509v1CertificateBuilder
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Calendar
import java.util.GregorianCalendar
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * Wraps [SecretKey] instances using a public/private key pair stored in
 * the platform [KeyStore]. This allows us to protect symmetric keys with
 * hardware-backed crypto, if provided by the device.
 *
 *
 * See [key wrapping](http://en.wikipedia.org/wiki/Key_Wrap) for more
 * details.
 *
 *
 * Not inherently thread safe.
 */
class SecretKeyWrapperOld
/**
 * Create a wrapper using the public/private key pair with the given alias.
 * If no pair with that alias exists, it will be generated.
 */
@Throws(GeneralSecurityException::class, IOException::class)
constructor(private val ctx: Context) {

    private val mCipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    private var mPair: KeyPair? = null

    init {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            createNewKey()
        }
        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        val entry = keyStore.getEntry(
            KEY_ALIAS, null
        ) as KeyStore.PrivateKeyEntry
        mPair = KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    private fun createNewKey() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
        try {
            generateKeyPair(ctx, KEY_ALIAS)

        } catch (e: Exception) {
            try {
                generateKeyPair2(KEY_ALIAS, keyStore)
            } catch (e2: Exception) {
            }

        }

        val entry = keyStore.getEntry(
            KEY_ALIAS, null
        ) as KeyStore.PrivateKeyEntry
        mPair = KeyPair(entry.certificate.publicKey, entry.privateKey)
    }

    @Throws(GeneralSecurityException::class)
    private fun generateKeyPair(context: Context, alias: String) {
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 100)

        val spec = KeyPairGeneratorSpec.Builder(context)
            .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
            .setAlias(alias)
            .setSubject(X500Principal("CN=$alias"))
            .setSerialNumber(BigInteger.ONE)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .setKeySize(2048)
            .build()
        val gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        gen.initialize(spec)
        gen.generateKeyPair()
    }

    @Throws(GeneralSecurityException::class)
    private fun generateKeyPair2(alias: String, keyStore: KeyStore) {
        val initialLocale = Locale.getDefault()
        setLocale(Locale.ENGLISH)
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), SecureRandom())
        val pair = gen.generateKeyPair()
        //generate self signed cert
        val x500Name = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, alias).build()
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 100)
        val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.public.encoded)
        val v1CertGen = X509v1CertificateBuilder(
            x500Name,
            BigInteger.ONE,
            start.time,
            end.time,
            x500Name,
            subjectPublicKeyInfo
        )
        try {
            val sigGen = JcaContentSignerBuilder("SHA256withRSA").build(pair.private)
            // Self sign :
            val x509CertificateHolder = v1CertGen.build(sigGen)
            val certificateFactory = CertificateFactory.getInstance("X.509")
            val cert =
                certificateFactory.generateCertificate(ByteArrayInputStream(x509CertificateHolder.encoded))
            keyStore.setKeyEntry(alias, pair.private, null, arrayOf(cert))
        } catch (e: Exception) {
        } finally {
            setLocale(initialLocale)
        }
    }

    /**
     * Sets default locale.
     */
    private fun setLocale(locale: Locale) {
        Locale.setDefault(locale)
        val resources = ctx.resources
        val config = resources.configuration
        config.locale = locale
        resources.updateConfiguration(config, resources.displayMetrics)
    }

    /**
     * Wrap a [SecretKey] using the public key assigned to this wrapper.
     * Use [.unwrap] to later recover the original
     * [SecretKey].
     *
     * @return a wrapped version of the given [SecretKey] that can be
     * safely stored on untrusted storage.
     */
    @Throws(GeneralSecurityException::class)
    fun wrap(key: SecretKey): ByteArray {
        mCipher.init(Cipher.WRAP_MODE, mPair!!.public)
        return mCipher.wrap(key)
    }

    /**
     * Unwrap a [SecretKey] using the private key assigned to this
     * wrapper.
     *
     * @param blob a wrapped [SecretKey] as previously returned by
     * [.wrap].
     */
    @Throws(GeneralSecurityException::class)
    fun unwrap(blob: ByteArray): SecretKey {
        mCipher.init(Cipher.UNWRAP_MODE, mPair!!.private)
        return mCipher.unwrap(blob, "AES", Cipher.SECRET_KEY) as SecretKey
    }

    companion object {
        private val KEY_ALIAS = "secret_wrapper_key"
    }
}
