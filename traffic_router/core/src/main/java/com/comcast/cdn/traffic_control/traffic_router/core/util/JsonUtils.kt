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

import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode

object JsonUtils {
    @Throws(JsonUtilsException::class)
    fun getLong(jsonNode: JsonNode?, key: String?): Long {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key).asLong()
    }

    @JvmOverloads
    fun optLong(jsonNode: JsonNode?, key: String?, d: Long = 0): Long {
        return if (jsonNode == null || !jsonNode.has(key)) {
            d
        } else jsonNode[key].asLong(d)
    }

    @Throws(JsonUtilsException::class)
    fun getDouble(jsonNode: JsonNode?, key: String?): Double {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key).asDouble()
    }

    @JvmOverloads
    fun optDouble(jsonNode: JsonNode?, key: String?, d: Double = 0.0): Double {
        return if (jsonNode == null || !jsonNode.has(key)) {
            d
        } else jsonNode[key].asDouble(d)
    }

    @Throws(JsonUtilsException::class)
    fun getInt(jsonNode: JsonNode?, key: String?): Int {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key).asInt()
    }

    @JvmOverloads
    fun optInt(jsonNode: JsonNode?, key: String?, d: Int = 0): Int {
        return if (jsonNode == null || !jsonNode.has(key)) {
            d
        } else jsonNode[key].asInt(d)
    }

    @Throws(JsonUtilsException::class)
    fun getBoolean(jsonNode: JsonNode?, key: String?): Boolean {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key).asBoolean()
    }

    @JvmOverloads
    fun optBoolean(jsonNode: JsonNode?, key: String?, d: Boolean = false): Boolean {
        return if (jsonNode == null || !jsonNode.has(key)) {
            d
        } else jsonNode[key].asBoolean(d)
    }

    @Throws(JsonUtilsException::class)
    fun getString(jsonNode: JsonNode?, key: String?): String? {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key).asText()
    }

    @JvmOverloads
    fun optString(jsonNode: JsonNode?, key: String?, d: String? = ""): String? {
        return if (jsonNode == null || !jsonNode.has(key)) {
            d
        } else jsonNode[key].asText(d)
    }

    @Throws(JsonUtilsException::class)
    fun getJsonNode(jsonNode: JsonNode?, key: String?): JsonNode? {
        if (jsonNode == null || !jsonNode.has(key)) {
            JsonUtils.throwException(key)
        }
        return jsonNode.get(key)
    }

    @Throws(JsonUtilsException::class)
    fun throwException(key: String?) {
        throw JsonUtilsException("Failed querying JSON for key: $key")
    }
}