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

import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import java.util.Collections
import java.util.SortedMap
import java.util.TreeMap

class ConsistentHasher {
    private val hashFunction: MD5HashFunction? = MD5HashFunction()
    fun <T : Hashable<*>?> selectHashable(hashables: MutableList<T?>?, dispersion: Dispersion?, s: String?): T? {
        val selectedHashables = selectHashables(hashables, dispersion, s)
        return if (!selectedHashables.isEmpty()) selectedHashables.get(0) else null
    }

    fun <T : Hashable<*>?> selectHashables(hashables: MutableList<T?>?, s: String?): MutableList<T?>? {
        return selectHashables(hashables, null, s)
    }

    fun <T : Hashable<*>?> selectHashables(
        hashables: MutableList<T?>?,
        dispersion: Dispersion?,
        s: String?
    ): MutableList<T?>? {
        val sortedHashables = sortHashables(hashables, s)
        val selectedHashables: MutableList<T?> = ArrayList()
        for (hashable in sortedHashables.values) {
            if (dispersion != null && selectedHashables.size >= dispersion.limit) {
                break
            }
            selectedHashables.add(hashable)
        }
        if (dispersion != null && dispersion.isShuffled) {
            Collections.shuffle(selectedHashables)
        }
        return selectedHashables
    }

    private fun <T : Hashable<*>?> sortHashables(hashables: MutableList<T?>?, s: String?): SortedMap<Double?, T?>? {
        val hash = hashFunction.hash(s)
        val hashableMap: SortedMap<Double?, T?> = TreeMap()
        val zeroHashes: MutableList<T?> = ArrayList()
        for (hashable in hashables) {
            if (!hashable.hasHashes()) {
                zeroHashes.add(hashable)
                continue
            }
            val closestHash = hashable.getClosestHash(hash)
            val hashDelta = getSafePositiveHash(hashableMap, Math.abs(hash - closestHash))
            hashableMap[hashDelta] = hashable
        }
        return synthesizeZeroHashes(hashableMap, zeroHashes)
    }

    /*
	 * The following provides the ability to use zero weights/hashCounts, with or without ordering. The primary
	 * use case is for multi-location routing, but this could also apply to caches. See TC-261.
	 * Because this method returns a SortedMap, we need a means to find the "lowest" and "highest" values in the
	 * hashableMap, then decrement or increment that number within the bounds of Double such that we don't wrap.
	 * Wrapping is dangerous, as it could cause something intended for the tail of the list to appear at the head.
	 */
    private fun <T : Hashable<*>?> synthesizeZeroHashes(
        hashableMap: SortedMap<Double?, T?>?,
        zeroHashes: MutableList<T?>?
    ): SortedMap<Double?, T?>? {
        if (zeroHashes.isEmpty()) {
            return hashableMap
        }
        var minHash = 0.0
        var maxHash = 0.0
        try {
            minHash = hashableMap.firstKey()
            maxHash = hashableMap.lastKey()
        } catch (ex: NoSuchElementException) {
            // hashableMap is empty; ignore
        }
        Collections.sort(zeroHashes) // sort by order if specified, default is 0 if unspecified

        // add any hashables that don't have hashes to the head/tail of the SortedMap
        for (hashable in zeroHashes) {
            if (hashable.getOrder() >= 0) { // append
                val syntheticHash = getSafePositiveHash(hashableMap, maxHash)
                hashableMap[syntheticHash] = hashable
                maxHash = syntheticHash
            } else { // negative order specified, prepend
                val syntheticHash = getSafeNegativeHash(hashableMap, minHash)
                hashableMap[syntheticHash] = hashable
                minHash = syntheticHash
            }
        }
        return hashableMap
    }

    private fun <T : Hashable<*>?> getSafePositiveHash(hashableMap: SortedMap<Double?, T?>?, hash: Double): Double {
        return getSafeHash(hashableMap, hash, true)
    }

    private fun <T : Hashable<*>?> getSafeNegativeHash(hashableMap: SortedMap<Double?, T?>?, hash: Double): Double {
        return getSafeHash(hashableMap, hash, false)
    }

    private fun <T : Hashable<*>?> getSafeHash(
        hashableMap: SortedMap<Double?, T?>?,
        hash: Double,
        add: Boolean
    ): Double {
        if (!hashableMap.containsKey(hash)) {
            return hash
        }
        var syntheticHash = hash
        var bits = java.lang.Double.doubleToLongBits(syntheticHash)
        do {
            bits = if (add) ++bits else --bits
            syntheticHash = java.lang.Double.longBitsToDouble(bits)
        } while (hashableMap.containsKey(syntheticHash))

        /*
		 * This shouldn't happen unless we wrap, return safest option if we do, replacing whatever key exists.
		 * If we return a wrapped value, we could incorrectly put the hashable at the head or tail of the SortedMap.
		 */return if (add && syntheticHash < hash || !add && syntheticHash > hash) {
            hash
        } else syntheticHash
    }
}