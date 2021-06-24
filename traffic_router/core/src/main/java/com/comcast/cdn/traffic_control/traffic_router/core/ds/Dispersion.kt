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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.fasterxml.jackson.databind.JsonNode
import java.util.Collections
import java.util.Random
import java.util.SortedMap

class Dispersion(dsJo: JsonNode?) {
    private var limit: Int = Dispersion.Companion.DEFAULT_LIMIT
    private var shuffled: Boolean = Dispersion.Companion.DEFAULT_SHUFFLED
    fun getLimit(): Int {
        return limit
    }

    private fun setLimit(limit: Int) {
        this.limit = limit
    }

    fun isShuffled(): Boolean {
        return shuffled
    }

    private fun setShuffled(shuffled: Boolean) {
        this.shuffled = shuffled
    }

    // Used by Http Routing functions
    fun getCache(cacheMap: SortedMap<Double?, Cache?>?): Cache? {
        if (cacheMap == null) {
            return null
        }
        val cacheList = getCacheList(cacheMap)
        return cacheList?.get(0)
    }

    // Used by DNS Routing functions
    fun getCacheList(cacheMap: SortedMap<Double?, Cache?>?): MutableList<Cache?>? {
        if (cacheMap == null) {
            return null
        }
        val cacheList: MutableList<Cache?> = ArrayList()
        for (c in cacheMap.values) {
            cacheList.add(c)
            if (getLimit() != 0 && cacheList.size == getLimit()) {
                break
            }
        }
        if (cacheList.size > 1 && isShuffled()) {
            Collections.shuffle(cacheList, Random())
        }
        return cacheList
    }

    companion object {
        const val DEFAULT_LIMIT = 1
        const val DEFAULT_SHUFFLED = true
    }

    init {
        val jo = dsJo.get("dispersion")
        if (jo != null) {
            val limit = JsonUtils.optInt(jo, "limit", Dispersion.Companion.DEFAULT_LIMIT)
            if (limit != 0) {
                setLimit(limit)
            }
            setShuffled(JsonUtils.optBoolean(jo, "shuffled", Dispersion.Companion.DEFAULT_SHUFFLED))
        } else if (dsJo.has("maxDnsIpsForLocation")) {
            // if no specific dispersion, use maxDnsIpsForLocation (should be DNS DSs only)
            setLimit(dsJo.get("maxDnsIpsForLocation").asInt(Dispersion.Companion.DEFAULT_LIMIT))
        }
    }
}