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
package com.comcast.cdn.traffic_control.traffic_router.core.dns

import org.xbill.DNS.RRset
import org.xbill.DNS.Record

class RRsetKey(private val rrset: RRset?) {
    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as RRsetKey?
        val thisIterator = rrset.rrs(false)
        val thatIterator = that.rrset.rrs(false)
        while (thisIterator.hasNext() && thatIterator.hasNext()) {
            if (thisIterator.next() != thatIterator.next()) {
                return false
            }
        }
        return !thisIterator.hasNext() && !thatIterator.hasNext()
    }

    override fun hashCode(): Int {
        var hashCode = 1
        val it = rrset.rrs(false)
        while (it.hasNext()) {
            val r = it.next() as Record?
            hashCode = 31 * hashCode + (r?.hashCode() ?: 0)
        }
        return hashCode
    }
}