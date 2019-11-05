package com.example.encryptiondecryption

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyProperties
import com.example.encryptiondecryption.security_utils.AsymmetricKeysHelper
import com.example.encryptiondecryption.security_utils.SecretKeyWrapperHelper
import com.example.encryptiondecryption.security_utils.SymmetricKeysHelper
import com.example.encryptiondecryption.security_utils.api_above_23.*
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    private lateinit var symmetricKeysHelper: SymmetricKeysHelper
    private lateinit var secretKeyWrapperHelper: SecretKeyWrapperHelper
    private lateinit var asymmetricKeysHelper: AsymmetricKeysHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT > 23) {
            symmetricKeysHelper = SymmetricKeysHelperNew("symmetric_key")
            secretKeyWrapperHelper = SecretKeyWrapperHelperNew(this)
            asymmetricKeysHelper = AsymmetricKeysHelperNew().apply {
                alias = "asymmetricKeysHelper"
                keyAlgorithm = KeyProperties.KEY_ALGORITHM_RSA
            }
            asymmetricKeysHelper.createKeys()
        } else {
            symmetricKeysHelper = SymmetricKeysHelperOld(this)
            asymmetricKeysHelper = AsymmetricKeysHelperOld(this)
            secretKeyWrapperHelper = SecretKeyWrapperHelperOld(this)
        }

        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)
        supportActionBar?.title = ""
        toolbar.title = "Secure"

        encrypt_symmetric_b.setOnClickListener {
            val encrypedData = symmetricKeysHelper.encryptSymmetric(input_et.text.toString())
            symmetric_tv.text = encrypedData
            symmetric_tv.tag = encrypedData
        }

        decrypt_symmetric_b.setOnClickListener {
            symmetric_tv.text = symmetricKeysHelper.decryptSymmetric(symmetric_tv.tag as String)
        }

        digest_b.setOnClickListener {
            message_digest_tv.text = String(symmetricKeysHelper.digest(input_et.text.toString()))
        }

        sign_b.setOnClickListener {
            val signature = asymmetricKeysHelper.signData(input_et.text.toString())
            signature?.let {
                signature_tv?.text = it
                signature_tv?.tag = it
            }
        }

        verify_b.setOnClickListener {
            signature_tv?.tag?.let {
                verify_result_tv?.text = asymmetricKeysHelper.verifyData(input_et.text.toString(), it as String).toString()
            }
        }

        encrypt_asymmetric_b.setOnClickListener {
            val encrypted = asymmetricKeysHelper.encryptByPublicKey(input_et?.text?.toString() ?: "")
            asymmetric_tv?.text = encrypted
            asymmetric_tv?.tag = encrypted
        }

        decrypt_asymmetric_b.setOnClickListener {
            asymmetric_tv?.text = asymmetricKeysHelper.decryptByPrivateKey(asymmetric_tv?.tag as? String ?: "")
        }

        encrypt_key_wrapper_b.setOnClickListener {
            val encrypted = secretKeyWrapperHelper.encryptWithWrappedKey(input_et?.text?.toString() ?: "")
            key_wrapper_tv?.text = encrypted
            key_wrapper_tv?.tag = encrypted
        }

        decrypt_key_wrapper_b.setOnClickListener {
            key_wrapper_tv?.text = secretKeyWrapperHelper.decryptWithWrappedKey(key_wrapper_tv?.tag as? String ?: "")
        }

    }
}
