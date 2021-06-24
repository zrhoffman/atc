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
package com.comcast.cdn.traffic_control.traffic_router.shared

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty

@JsonIgnoreProperties(ignoreUnknown = true)
class Certificate {
    @JsonProperty
    private var crt: String? = null

    @JsonProperty
    private var key: String? = null
    fun getCrt(): String? {
        return crt
    }

    fun setCrt(crt: String?) {
        this.crt = crt
    }

    fun getKey(): String? {
        return key
    }

    fun setKey(key: String?) {
        this.key = key
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as Certificate?
        if (if (crt != null) crt != that.crt else that.crt != null) return false
        return if (key != null) key == that.key else that.key == null
    }

    override fun hashCode(): Int {
        var result = if (crt != null) crt.hashCode() else 0
        result = 31 * result + if (key != null) key.hashCode() else 0
        return result
    }
}