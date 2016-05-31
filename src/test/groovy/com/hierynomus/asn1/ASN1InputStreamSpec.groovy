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
package com.hierynomus.asn1

import com.hierynomus.asn1.encodingrules.ber.BERDecoder
import spock.lang.Specification

class ASN1InputStreamSpec extends Specification {

  def "does not support indefinite length encoding"() {
    given:
    def is = new ASN1InputStream(new BERDecoder(), [0x23, 0x80, 0x03, 0x02, 0xF0, 0xF0, 0x03, 0x02, 0x02, 0xF4, 0x0, 0x0] as byte[])

    when:
    is.readObject()

    then:
    def ex = thrown(ASN1ParseException.class)
    ex.getMessage() == "The indefinite length form is not (yet) supported!"
  }
}
