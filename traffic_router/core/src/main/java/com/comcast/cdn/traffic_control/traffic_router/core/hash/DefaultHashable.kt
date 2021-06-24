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
package com.comcast.cdn.traffic_control.traffic_router.core.hash

import java.util.Arrays
import java.util.TreeSet

open class DefaultHashable : Hashable<DefaultHashable?>, Comparable<DefaultHashable?> {
    private var hashes: Array<Double?>?
    private var order = 0
    override fun setOrder(order: Int) {
        this.order = order
    }

    override fun getOrder(): Int {
        return order
    }

    override fun hasHashes(): Boolean {
        return if (hashes.size > 0) true else false
    }

    override fun getClosestHash(hash: Double): Double {
        return hashes.get(NumberSearcher.findClosest(hashes, hash))
    }

    override fun generateHashes(hashId: String?, hashCount: Int): DefaultHashable? {
        val hashSet = TreeSet<Double?>()
        val hashFunction = MD5HashFunction()
        for (i in 0 until hashCount) {
            hashSet.add(hashFunction.hash("$hashId--$i"))
        }
        hashes = arrayOfNulls<Double?>(hashSet.size)
        System.arraycopy(hashSet.toTypedArray(), 0, hashes, 0, hashSet.size)
        return this
    }

    override fun getHashValues(): MutableList<Double?>? {
        return Arrays.asList(*hashes)
    }

    override fun compareTo(o: DefaultHashable?): Int {
        return if (getOrder() < 0 && o.getOrder() < 0) {
            if (getOrder() < o.getOrder()) 1 else if (getOrder() > o.getOrder()) -1 else 0
        } else {
            if (getOrder() < o.getOrder()) -1 else if (getOrder() > o.getOrder()) 1 else 0
        }
    }
}