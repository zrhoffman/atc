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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableTreeSet

class FederationMapping(
    private val cname: String?,
    private val ttl: Int,
    resolve4: ComparableTreeSet<CidrAddress?>?,
    resolve6: ComparableTreeSet<CidrAddress?>?
) : Comparable<FederationMapping?> {
    private val resolve4: ComparableTreeSet<CidrAddress?>? = ComparableTreeSet()
    private val resolve6: ComparableTreeSet<CidrAddress?>? = ComparableTreeSet()
    fun getCname(): String? {
        return cname
    }

    fun getTtl(): Int {
        return ttl
    }

    fun getResolve4(): ComparableTreeSet<CidrAddress?>? {
        return resolve4
    }

    fun getResolve6(): ComparableTreeSet<CidrAddress?>? {
        return resolve6
    }

    fun getResolveAddresses(cidrAddress: CidrAddress?): ComparableTreeSet<CidrAddress?>? {
        return if (cidrAddress.isIpV6()) getResolve6() else getResolve4()
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as FederationMapping?
        if (ttl != that.ttl) return false
        if (if (cname != null) cname != that.cname else that.cname != null) return false
        return if (if (resolve4 != null) resolve4 != that.resolve4 else that.resolve4 != null) false else !if (resolve6 != null) resolve6 != that.resolve6 else that.resolve6 != null
    }

    override fun hashCode(): Int {
        var result = cname?.hashCode() ?: 0
        result = 31 * result + ttl
        result = 31 * result + (resolve4?.hashCode() ?: 0)
        result = 31 * result + (resolve6?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "FederationMapping{" +
                "cname='" + cname + '\'' +
                ", ttl=" + ttl +
                ", resolve4=" + resolve4 +
                ", resolve6=" + resolve6 +
                '}'
    }

    // Compare to does not mean that a result of zero means that a.equals(b) is true
    override fun compareTo(other: FederationMapping?): Int {
        if (other == null) {
            return -1
        }
        var result = cname.compareTo(other.cname)
        if (result != 0) {
            return result
        }
        result = ttl - other.ttl
        if (result != 0) {
            return result
        }
        result = resolve4.compareTo(other.resolve4)
        return if (result != 0) {
            result
        } else resolve6.compareTo(other.resolve6)
    }

    fun containsCidrAddress(cidrAddress: CidrAddress?): Boolean {
        return resolve4.contains(cidrAddress) || resolve6.contains(cidrAddress)
    }

    fun getResolve4Matches(cidrAddress: CidrAddress?): ComparableTreeSet<CidrAddress?>? {
        return getResolveMatches(resolve4, cidrAddress)
    }

    fun getResolve6Matches(cidrAddress: CidrAddress?): ComparableTreeSet<CidrAddress?>? {
        return getResolveMatches(resolve6, cidrAddress)
    }

    protected fun getResolveMatches(
        resolves: MutableSet<CidrAddress?>?,
        cidrAddress: CidrAddress?
    ): ComparableTreeSet<CidrAddress?>? {
        val cidrAddresses = ComparableTreeSet<CidrAddress?>()
        for (cidrAddressResolve4 in resolves) {
            if (cidrAddressResolve4.includesAddress(cidrAddress)) {
                cidrAddresses.add(cidrAddressResolve4)
            }
        }
        return cidrAddresses
    }

    fun createFilteredMapping(cidrAddress: CidrAddress?): FederationMapping? {
        return FederationMapping(cname, ttl, getResolve4Matches(cidrAddress), getResolve6Matches(cidrAddress))
    }

    init {
        this.resolve4.addAll(resolve4)
        this.resolve6.addAll(resolve6)
    }
}