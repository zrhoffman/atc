/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.comcast.cdn.traffic_control.traffic_router.core.util

import org.apache.commons.codec.binary.Base64
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec

class StringProtector(passwd: String?) {
    private val base64: Base64? = Base64(true)
    private val encryptor: Cipher?
    private val decryptor: Cipher?

    @Throws(GeneralSecurityException::class, UnsupportedEncodingException::class)
    fun encrypt(property: ByteArray?): ByteArray? {
        return encryptor.doFinal(property)
    }

    @Throws(UnsupportedEncodingException::class, GeneralSecurityException::class)
    fun encrypt(property: String?): String? {
        return base64.encodeAsString(encrypt(property.toByteArray(charset("UTF-8"))))
    }

    @Throws(UnsupportedEncodingException::class, GeneralSecurityException::class)
    fun encryptForUrl(data: ByteArray?): String? {
        return base64.encodeAsString(encrypt(data))
    }

    @Throws(UnsupportedEncodingException::class, GeneralSecurityException::class)
    fun encodeForUrl(data: ByteArray?): String? {
        return base64.encodeAsString(data)
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    fun decrypt(property: ByteArray?): ByteArray? {
        return decryptor.doFinal(property)
    }

    @Throws(GeneralSecurityException::class, IOException::class)
    fun decrypt(property: String?): String? {
        val bytes = decrypt(base64.decode(property))
        return String(bytes, "UTF-8")
    } //	public static void main(final String[] args) throws Exception {

    //		StringProtector sp = new StringProtector("my passwd");
    //		String originalPassword = "secret";
    ////		System.out.println("Original password: " + originalPassword);
    //		String encryptedPassword = sp.encrypt(originalPassword);
    ////		System.out.println("Encrypted password: " + encryptedPassword);
    //		String decryptedPassword = sp.decrypt(encryptedPassword);
    ////		System.out.println("Decrypted password: " + decryptedPassword);
    //	}
    companion object {
        private val SALT: ByteArray? = byteArrayOf(
            0xde as Byte, 0x33 as Byte, 0x10 as Byte, 0x12 as Byte,
            0xde as Byte, 0x33 as Byte, 0x10 as Byte, 0x12 as Byte
        )
    }

    init {
        val keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
        val key = keyFactory.generateSecret(PBEKeySpec(passwd.toCharArray()))
        encryptor = Cipher.getInstance("PBEWithMD5AndDES")
        encryptor.init(Cipher.ENCRYPT_MODE, key, PBEParameterSpec(StringProtector.Companion.SALT, 20))
        decryptor = Cipher.getInstance("PBEWithMD5AndDES")
        decryptor.init(Cipher.DECRYPT_MODE, key, PBEParameterSpec(StringProtector.Companion.SALT, 20))
    }
}