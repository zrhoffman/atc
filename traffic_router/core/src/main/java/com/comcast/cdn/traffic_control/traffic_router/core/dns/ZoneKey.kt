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

import org.xbill.DNS.Name
import org.xbill.DNS.Record
import java.util.Collections
import java.util.Date

open class ZoneKey(name: Name?, records: MutableList<Record?>?) : Comparable<ZoneKey?> {
    private var name: Name? = null
    protected var records: MutableList<Record?>? = null
    private var initialHashCode = 0
    private var timestamp: Long = 0
    fun getName(): Name? {
        return name
    }

    private fun setName(name: Name?) {
        this.name = name
    }

    fun getRecords(): MutableList<Record?>? {
        return records
    }

    private fun setRecords(records: MutableList<Record?>?) {
        this.records = records
    }

    private fun getInitialHashCode(): Int {
        return initialHashCode
    }

    private fun setInitialHashCode(initialHashCode: Int) {
        this.initialHashCode = initialHashCode
    }

    fun getTimestamp(): Long {
        return timestamp
    }

    private fun setTimestamp(timestamp: Long) {
        this.timestamp = timestamp
    }

    fun updateTimestamp() {
        timestamp = System.currentTimeMillis()
    }

    fun getTimestampDate(): Date? {
        return Date(getTimestamp())
    }

    override fun hashCode(): Int {
        return getName().hashCode() + getInitialHashCode()
    }

    override fun equals(obj: Any?): Boolean {
        val ozk = obj as ZoneKey?
        return getName() == ozk.getName() && getInitialHashCode() == ozk.getInitialHashCode() && obj.javaClass == this.javaClass
    }

    // this correctly sorts the names such that the superDomains are last
    override fun compareTo(zk: ZoneKey?): Int {
        val i = name.compareTo(zk.getName())
        return if (i < 0) {
            1
        } else if (i > 0) {
            -1
        } else {
            0
        }
    }

    init {
        /*
		 * Per the canonical format in  RFC 4034, the records must be in order when the RRset is signed;
		 * sort here to ensure consistency with the ZoneKey, which is based on the hashCode of the List<Record>.
		 * Because we want one set of Records per ZoneKey, regardless of whether DNSSEC is enabled, sort in
		 * this constructor, which is inherited by SignedZoneKey.
		 */
        Collections.sort(records)
        setName(name)
        setRecords(records)
        setInitialHashCode(records.hashCode()) // if the records are signed, the hashCode will change
        setTimestamp(System.currentTimeMillis())
    }
}