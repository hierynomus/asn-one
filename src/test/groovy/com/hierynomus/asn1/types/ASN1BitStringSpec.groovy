/*
 *    Copyright 2016 Jeroen van Erp <jeroen@hierynomus.com>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package com.hierynomus.asn1.types

import com.hierynomus.asn1.ASN1InputStream
import com.hierynomus.asn1.types.string.ASN1BitString
import spock.lang.Specification

class ASN1BitStringSpec extends Specification {

  def "should parse an ASN.1 BIT STRING"() {
    given:
    def object = new ASN1InputStream(bytes as byte[]).readObject()
    expect:
    object instanceof ASN1BitString
    with(object as ASN1BitString) { ASN1BitString bs ->
      bs.length() == length
      (0..length - 1).every {
        bs.isSet(it) == (values[it] == 1)
      }
    }

    where:
    bytes                                | length | values
    [0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4] | 22     | [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1]
  }
}
