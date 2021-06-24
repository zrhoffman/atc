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
package geolocation

import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.junit.Assert
import org.junit.Before
import org.junit.Test

class GeolocationTest {
    @Before
    @Throws(Exception::class)
    fun setUp() {
    }

    @Test
    fun testGetDistanceFrom() {
        val l1 = Geolocation(0f, 0f)
        val l2 = Geolocation(.5f, .5f)
        val expected = 78.6
        val actual = l1.getDistanceFrom(l2)
        Assert.assertEquals(expected, actual, 0.1)
    }

    @Test
    fun testGetDistanceFromEquator() {
        val l1 = Geolocation(1f, 0f)
        val l2 = Geolocation(-1f, 0f)
        val expected = 222.4
        val actual = l1.getDistanceFrom(l2)
        Assert.assertEquals(expected, actual, 0.1)
    }

    @Test
    fun testGetDistanceFromIntlDateLine() {
        val l1 = Geolocation(0f, 179f)
        val l2 = Geolocation(0f, -179f)
        val expected = 222.4
        val actual = l1.getDistanceFrom(l2)
        Assert.assertEquals(expected, actual, 0.1)
    }

    @Test
    fun testGetDistanceFromNull() {
        val l1 = Geolocation(0f, 1f)
        val l2: Geolocation? = null
        val expected = Double.POSITIVE_INFINITY
        val actual = l1.getDistanceFrom(l2)
        Assert.assertEquals(expected, actual, 0.1)
    }

    @Test
    fun testGetDistanceFromPrimeMeridian() {
        val l1 = Geolocation(0f, 1f)
        val l2 = Geolocation(0f, -1f)
        val expected = 222.4
        val actual = l1.getDistanceFrom(l2)
        Assert.assertEquals(expected, actual, 0.1)
    }
}