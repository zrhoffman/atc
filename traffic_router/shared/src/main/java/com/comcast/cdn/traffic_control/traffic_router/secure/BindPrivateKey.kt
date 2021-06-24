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

import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import org.apache.log4j.Logger
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.RSAPrivateCrtKeySpec
import java.util.Arrays
import java.util.Base64

class BindPrivateKey {
    private fun decodeBigInt(s: String?): BigInteger? {
        return BigInteger(1, Base64.getDecoder().decode(s.toByteArray()))
    }

    private fun decodeBigIntegers(s: String?): MutableMap<String?, BigInteger?>? {
        val bigIntKeys = Arrays.asList(
            "Modulus", "PublicExponent", "PrivateExponent", "Prime1", "Prime2", "Exponent1", "Exponent2", "Coefficient"
        )
        val bigIntegerMap: MutableMap<String?, BigInteger?> = HashMap()
        for (line in s.split("\n".toRegex()).toTypedArray()) {
            val tokens: Array<String?> = line.split(": ".toRegex()).toTypedArray()
            if (bigIntKeys.stream().filter { k: String? -> k == tokens[0] }.findFirst().isPresent) {
                bigIntegerMap[tokens[0]] = decodeBigInt(tokens[1])
            }
        }
        return bigIntegerMap
    }

    fun decode(data: String?): PrivateKey? {
        val map = decodeBigIntegers(data)
        val modulus = map.get("Modulus")
        val publicExponent = map.get("PublicExponent")
        val privateExponent = map.get("PrivateExponent")
        val prime1 = map.get("Prime1")
        val prime2 = map.get("Prime2")
        val exp1 = map.get("Exponent1")
        val exp2 = map.get("Exponent2")
        val coeff = map.get("Coefficient")
        val keySpec = RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, prime1, prime2, exp1, exp2, coeff)
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec)
        } catch (e: Exception) {
            LOGGER.error("Failed to decode Bind Private Key data: " + e.message, e)
        }
        return null
    }

    companion object {
        private val LOGGER = Logger.getLogger(BindPrivateKey::class.java)
    }
}