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
package com.comcast.cdn.traffic_control.traffic_router.core.edge

import org.xbill.DNS.Type
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

class InetRecord {
    private val ad: InetAddress?
    private val ttl: Long
    private val type: Int
    private val target: String?

    constructor(ad: InetAddress?, ttl: Long) {
        this.ad = ad
        this.ttl = ttl
        target = null
        type = if (ad is Inet4Address) Type.A else Type.AAAA
    }

    constructor(alias: String?, ttl: Long) {
        ad = null
        this.ttl = ttl
        target = alias
        type = Type.CNAME
    }

    constructor(target: String?, ttl: Long, type: Int) {
        ad = null
        this.target = target
        this.ttl = ttl
        this.type = type
    }

    fun isInet4(): Boolean {
        return ad is Inet4Address
    }

    fun isInet6(): Boolean {
        return ad is Inet6Address
    }

    fun getTTL(): Long {
        return ttl
    }

    fun getAddress(): InetAddress? {
        return ad
    }

    override fun toString(): String {
        return "InetRecord{" +
                "ad=" + ad +
                ", ttl=" + ttl +
                ", target='" + target + '\'' +
                ", type=" + Type.string(type) +
                '}'
    }

    fun isAlias(): Boolean {
        return target != null && type == Type.CNAME
    }

    fun getAlias(): String? {
        return target
    }

    fun getTarget(): String? {
        return target
    }

    fun getType(): Int {
        return type
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as InetRecord?
        if (ttl != that.ttl || type != that.type) return false
        return if (if (ad != null) ad != that.ad else that.ad != null) false else !if (target != null) target != that.target else that.target != null
    }

    override fun hashCode(): Int {
        var result = ad?.hashCode() ?: 0
        result = 31 * result + (ttl xor (ttl ushr 32)) as Int
        result = 31 * result + (type xor (type ushr 32)) as Int
        result = 31 * result + (target?.hashCode() ?: 0)
        return result
    }
}