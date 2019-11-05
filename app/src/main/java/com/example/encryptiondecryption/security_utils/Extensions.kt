package com.example.encryptiondecryption.security_utils

import org.spongycastle.openssl.jcajce.JcaPEMWriter
import org.spongycastle.pkcs.PKCS10CertificationRequest
import java.io.StringWriter
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate

fun PKCS10CertificationRequest.toPem(): String {
    val w = StringWriter()
    JcaPEMWriter(w).use {
        it.writeObject(this)
    }
    return w.toString()
}

fun PrivateKey.toPem(): String {
    val w = StringWriter()
    JcaPEMWriter(w).use {
        it.writeObject(this)
    }
    return w.toString()
}

fun PublicKey.toPem(): String {
    val w = StringWriter()
    JcaPEMWriter(w).use {
        it.writeObject(this)
    }
    return w.toString()
}

fun Certificate.toPem(): String {
    val w = StringWriter()
    JcaPEMWriter(w).use {
        it.writeObject(this)
    }
    return w.toString()
}