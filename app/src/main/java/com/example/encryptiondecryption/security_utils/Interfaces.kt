package com.example.encryptiondecryption.security_utils

import javax.crypto.SecretKey

interface AsymmetricKeysHelper {

    fun createKeys()
    fun signData(inputStr: String): String?
    fun verifyData(input: String, signatureStr: String?): Boolean
    fun encryptByPublicKey(inputStr: String): String?
    fun decryptByPrivateKey(inputStr: String): String?
    fun deleteKeys()
}

interface SecretKeyWrapperHelper {

    fun encryptWithWrappedKey(text: String): String?
    fun decryptWithWrappedKey(text: String): String?
}

interface SecretKeyWrapper {

    fun wrap(key: SecretKey): ByteArray
    fun unwrap(blob: ByteArray): SecretKey
}

interface SymmetricKeysHelper {

    fun encryptSymmetric(text: String): String?
    fun digest(text: String): ByteArray
    fun decryptSymmetric(text: String): String?
}