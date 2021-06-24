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
import org.xbill.DNS.Type
import java.util.function.Consumer
import java.util.function.Function
import java.util.stream.Collectors

class RRSetsBuilder {
    private val recordsToRRSet: Function<MutableList<Record?>?, RRset?>? = Function { records: MutableList<Record?>? ->
        val rrSet = RRset()
        records.forEach(Consumer { r: Record? -> rrSet.addRR(r) })
        rrSet
    } as Function<MutableList<Record?>?, RRset?>
    private val rrSetComparator: Comparator<RRset?>? = label@ Comparator { rrSet1: RRset?, rrSet2: RRset? ->
        var x = rrSet1.getName().compareTo(rrSet2.getName())
        if (x != 0) {
            return@label x
        }
        x = rrSet1.getDClass() - rrSet2.getDClass()
        if (x != 0) {
            return@label x
        }
        if (rrSet1.getType() == Type.SOA) {
            return@label -1
        }
        if (rrSet2.getType() == Type.SOA) {
            return@label 1
        }
        rrSet1.getType() - rrSet2.getType()
    }

    fun build(records: MutableList<Record?>?): MutableList<RRset?>? {
        val map = records.stream().sorted().collect(
            Collectors.groupingBy(Function<Record?, String?> { record: Record? ->
                RRSetsBuilder.Companion.qualifer(
                    record
                )
            }, Collectors.toList())
        )
        return map.values.stream().map(recordsToRRSet).sorted(rrSetComparator).collect(Collectors.toList())
    }

    companion object {
        private fun qualifer(record: Record?): String? {
            return String.format(
                "%s %d %d %d",
                record.getName().toString(),
                record.getDClass(),
                record.getType(),
                record.getTTL()
            )
        }
    }
}