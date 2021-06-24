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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Arrays

class CidrAddress @JvmOverloads constructor(
    private val address: InetAddress?,
    private val netmaskLength: Int = address.getAddress().size * 8
) : Comparable<CidrAddress?> {
    private val hostBytes: ByteArray?
    private val maskBytes: ByteArray?
    fun getHostBytes(): ByteArray? {
        return hostBytes
    }

    fun getMaskBytes(): ByteArray? {
        return maskBytes
    }

    fun getNetmaskLength(): Int {
        return netmaskLength
    }

    fun includesAddress(other: CidrAddress?): Boolean {
        return if (netmaskLength >= other.netmaskLength) {
            false
        } else compareTo(other) == 0
    }

    fun isIpV6(): Boolean {
        return getHostBytes().size > 4
    }

    override fun compareTo(other: CidrAddress?): Int {
        var mask = maskBytes
        var len = netmaskLength
        if (netmaskLength > other.netmaskLength) {
            mask = other.maskBytes
            len = other.netmaskLength
        }
        val numNetmaskBytes = Math.ceil(len as Double / 8) as Int
        for (i in 0 until numNetmaskBytes) {
            val diff: Int = (hostBytes.get(i) and mask.get(i)) - (other.hostBytes.get(i) and mask.get(i))
            if (diff != 0) {
                return diff
            }
        }
        return 0
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as CidrAddress?
        if (netmaskLength != that.netmaskLength) return false
        if (!Arrays.equals(hostBytes, that.hostBytes)) return false
        return if (!Arrays.equals(maskBytes, that.maskBytes)) false else true
    }

    override fun hashCode(): Int {
        var result = if (hostBytes != null) Arrays.hashCode(hostBytes) else 0
        result = 31 * result + if (maskBytes != null) Arrays.hashCode(maskBytes) else 0
        result = 31 * result + netmaskLength
        return result
    }

    private fun getCidrString(): String? {
        return "CidrAddress{" + address.toString() + "/" + netmaskLength + "}"
    }

    override fun toString(): String {
        return getCidrString()
    }

    fun getAddressString(): String? {
        return address.toString() + "/" + netmaskLength
    }

    companion object {
        @Throws(NetworkNodeException::class)
        fun fromString(cidrString: String?): CidrAddress? {
            val hostNetworkArray: Array<String?> = cidrString.split("/".toRegex()).toTypedArray()
            val host = hostNetworkArray[0].trim { it <= ' ' }
            val address: InetAddress?
            address = try {
                InetAddress.getByName(host)
            } catch (ex: UnknownHostException) {
                throw NetworkNodeException(ex)
            }
            if (hostNetworkArray.size == 1) {
                return CidrAddress(address)
            }
            val netmaskLength: Int
            netmaskLength = try {
                hostNetworkArray[1].trim { it <= ' ' }.toInt()
            } catch (e: NumberFormatException) {
                throw NetworkNodeException(e)
            }
            return CidrAddress(address, netmaskLength)
        }
    }

    init {
        val addressBytes = address.getAddress()
        if (address is Inet4Address && (netmaskLength > 32 || netmaskLength < 0)) {
            throw NetworkNodeException("Rejecting IPv4 subnet with invalid netmask: " + getCidrString())
        } else if (address is Inet6Address && (netmaskLength > 128 || netmaskLength < 0)) {
            throw NetworkNodeException("Rejecting IPv6 subnet with invalid netmask: " + getCidrString())
        }
        hostBytes = addressBytes
        maskBytes = ByteArray(addressBytes.size)
        for (i in 0 until netmaskLength) {
            maskBytes[i / 8] = maskBytes[i / 8] or (1 shl 7 - i % 8)
        }
    }
}