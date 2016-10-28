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
package com.hierynomus.asn1.types.constructed

import com.hierynomus.asn1.types.ASN1Object
import com.hierynomus.asn1.types.constructed.ASN1Set
import com.hierynomus.asn1.types.primitive.ASN1Boolean
import com.hierynomus.asn1.types.primitive.ASN1Integer
import spock.lang.Specification

class ASN1SetSpec extends Specification {

  def "should not mutate the internal set of an ASN.1 SET"() {
    given:
    def set = new ASN1Set(new HashSet<ASN1Object>([new ASN1Boolean(true), new ASN1Integer(1)]))

    when:
    (set.value as Set).clear()

    then:
    set.size() == 2
  }

  def "should not mutate the internal set of an ASN.1 SET through the iterator"() {
    given:
    def set = new ASN1Set(new HashSet<ASN1Object>([new ASN1Boolean(true), new ASN1Integer(1)]))
    def iterator = set.iterator()

    when:
    iterator.next()
    iterator.remove()

    then:
    set.size() == 2
  }
}
