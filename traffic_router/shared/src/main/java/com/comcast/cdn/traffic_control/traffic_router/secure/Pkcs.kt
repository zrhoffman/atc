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
package com.comcast.cdn.traffic_control.traffic_router.secure

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.spec.KeySpec

abstract class Pkcs {
    private val data: String?
    private val privateKey: PrivateKey?
    private var publicKey: PublicKey? = null
    private var keySpec: KeySpec?
    private var publicKeySpec: KeySpec? = null

    constructor(data: String?) {
        this.data = data
        keySpec = toKeySpec(data)
        Security.addProvider(BouncyCastleProvider())
        privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(keySpec)
    }

    constructor(privateData: String?, publicData: String?) {
        data = privateData
        keySpec = toKeySpec(data)
        privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(keySpec)
        publicKeySpec = toKeySpec(publicData)
        publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(publicKeySpec)
    }

    fun getData(): String? {
        return data
    }

    fun getKeySpec(): KeySpec? {
        return keySpec
    }

    fun getPublicKeySpec(): KeySpec? {
        return publicKeySpec
    }

    fun setKeySpec(keySpec: KeySpec?) {
        this.keySpec = keySpec
    }

    fun getPrivateKey(): PrivateKey? {
        return privateKey
    }

    fun getPublicKey(): PublicKey? {
        return publicKey
    }

    abstract fun getHeader(): String?
    abstract fun getFooter(): String?
    private fun stripHeaderAndFooter(data: String?): String? {
        return data.replace(getHeader().toRegex(), "").replace(getFooter().toRegex(), "").replace("\\s".toRegex(), "")
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    protected abstract fun decodeKeySpec(data: String?): KeySpec?

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun toKeySpec(data: String?): KeySpec? {
        return decodeKeySpec(stripHeaderAndFooter(data))
    }
}