package com.example.encryptiondecryption

import org.junit.Test

import org.junit.Assert.*

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {
    @Test
    fun addition_isCorrect() {
        assertEquals(4, 2 + 2)
    }

    @Test
    fun tt() {
        val text = "abcd"
        val bytes = text.toByteArray()
        bytes.forEach { print(it) }
        println()
        println(String(bytes))
    }

    @Test
    fun ttt() {

    }
}