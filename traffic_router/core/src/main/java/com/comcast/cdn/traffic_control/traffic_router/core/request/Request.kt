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
package com.comcast.cdn.traffic_control.traffic_router.core.request

import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

open class Request {
    private var clientIP: String? = null
    private var hostname: String? = null
    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is Request) {
            val rhs = obj as Request?
            EqualsBuilder()
                .append(getClientIP(), rhs.getClientIP())
                .append(getHostname(), rhs.getHostname())
                .isEquals
        } else {
            false
        }
    }

    fun getClientIP(): String? {
        return clientIP
    }

    fun getHostname(): String? {
        return hostname
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(getClientIP())
            .append(getHostname())
            .toHashCode()
    }

    fun setClientIP(clientIP: String?) {
        this.clientIP = clientIP
    }

    fun setHostname(hostname: String?) {
        if (hostname == null) {
            this.hostname = null
            return
        }
        this.hostname = hostname.toLowerCase()
    }

    open fun getType(): String? {
        return "unknown"
    }
}