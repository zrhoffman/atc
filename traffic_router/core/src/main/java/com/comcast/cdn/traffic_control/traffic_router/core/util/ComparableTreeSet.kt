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

import java.util.TreeSet

class ComparableTreeSet<E> : TreeSet<E?>(), Comparable<ComparableTreeSet<E?>?> {
    override fun compareTo(o: ComparableTreeSet<E?>?): Int {
        if (isEmpty() && !o.isEmpty()) {
            return 1
        } else if (o.isEmpty()) {
            return -1
        }
        if (this == o) {
            return 0
        }
        if (containsAll(o)) {
            // this comes first because it is a superset??????
            return -1
        }
        if (o.containsAll(this)) {
            return 1
        }
        val item: Any? = first()
        val otherItem: Any? = o.first()
        return if (item is Comparable<*>) {
            (item as Comparable<*>?).compareTo(otherItem)
        } else item.hashCode() - otherItem.hashCode()
    }
}