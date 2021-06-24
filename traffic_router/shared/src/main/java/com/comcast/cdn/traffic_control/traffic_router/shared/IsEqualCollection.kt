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

import org.hamcrest.Description
import org.hamcrest.Factory
import org.hamcrest.Matcher
import org.hamcrest.core.IsEqual

class IsEqualCollection<T> private constructor(equalArg: T?) : IsEqual<T?>(equalArg) {
    private val expectedValue: Any?
    private fun describeItems(description: Description?, value: Any?) {
        if (value is MutableCollection<*>) {
            val items = (value as MutableCollection<*>?).toTypedArray()
            description.appendText("\n{")
            for (item in items) {
                description.appendText("\n\t")
                description.appendText(item.toString())
            }
            description.appendText("\n}")
        }
    }

    override fun describeTo(description: Description?) {
        if (expectedValue is MutableCollection<*>) {
            description.appendText("all of the following in order\n")
            describeItems(description, expectedValue)
            return
        }
        super.describeTo(description)
    }

    override fun describeMismatch(actualValue: Any?, mismatchDescription: Description?) {
        if (actualValue is MutableCollection<*>) {
            mismatchDescription.appendText("had the items\n")
            describeItems(mismatchDescription, actualValue)
            return
        }
        super.describeMismatch(actualValue, mismatchDescription)
    }

    companion object {
        @Factory
        fun <T> equalTo(operand: T?): Matcher<T?>? {
            return IsEqualCollection<T?>(operand)
        }
    }

    init {
        expectedValue = equalArg
    }
}