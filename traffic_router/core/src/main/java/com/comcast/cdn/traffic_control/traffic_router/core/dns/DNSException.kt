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

/**
 * An [Exception] that relates to a specified DNS RCODE.
 */
class DNSException : Exception {
    private val rcode: Int

    /**
     * @param rcode
     * the DNS RCODE associated with this exception.
     */
    constructor(rcode: Int) {
        this.rcode = rcode
    }

    /**
     * @param rcode
     * the DNS RCODE associated with this exception.
     * @param message
     * a human readable message associated with the exception
     */
    constructor(rcode: Int, message: String?) : super(message) {
        this.rcode = rcode
    }

    /**
     * @param rcode
     * the DNS RCODE associated with this exception.
     * @param message
     * a human readable message associated with the exception
     * @param cause
     * a chained throwable that caused this exception
     */
    constructor(rcode: Int, message: String?, cause: Throwable?) : super(message, cause) {
        this.rcode = rcode
    }

    /**
     * @param rcode
     * the DNS RCODE associated with this exception.
     * @param cause
     * a chained [Throwable] that caused this exception
     */
    constructor(rcode: Int, cause: Throwable?) : super(cause) {
        this.rcode = rcode
    }

    /**
     * Gets rcode.
     *
     * @return the rcode
     */
    fun getRcode(): Int {
        return rcode
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}