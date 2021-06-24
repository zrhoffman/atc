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

class ComparableStringByLength(string: String?) : Comparable<ComparableStringByLength?> {
    private val string: String?
    override fun compareTo(other: ComparableStringByLength?): Int {
        if (string.length == other.string.length) {
            return string.compareTo(other.string)
        }
        return if (string.length > other.string.length) -1 else 1
    }

    override fun toString(): String {
        return string
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null) {
            return false
        }
        if (javaClass != other.javaClass && String::class.java != other.javaClass) {
            return false
        }
        return if (String::class.java == other.javaClass) {
            string == other
        } else string == (other as ComparableStringByLength?).string
    }

    override fun hashCode(): Int {
        return string.hashCode()
    }

    init {
        require(!(string == null || string.length == 0)) { "String parameter must be non-null and non-empty" }
        this.string = string
    }
}