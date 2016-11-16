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
package com.hierynomus.asn1.types.primitive

import com.hierynomus.asn1.ASN1InputStream
import com.hierynomus.asn1.ASN1OutputStream
import com.hierynomus.asn1.encodingrules.ber.BERDecoder
import spock.lang.Specification
import spock.lang.Unroll

@Unroll
class ASN1ObjectIdentifierSpec extends Specification {

  def "should parse ASN.1 OBJECT IDENTIFIER with value #value"() {
    expect:
    new ASN1InputStream(new BERDecoder(), new ByteArrayInputStream(buffer as byte[])).readObject() == value

    where:
    buffer                                                             | value
    [0x06, 0x03, 0x55, 0x04, 0x03]                                     | new ASN1ObjectIdentifier("2.5.4.3")
    [0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14] | new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.20")
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02] | new ASN1ObjectIdentifier("1.2.840.113549.1.7.2")
  }

  @Unroll
  def "should write ASN.1 OBJECT IDENTIFIER #value as bytes #bytes"() {
    given:
    def stream = new ByteArrayOutputStream()

    when:
    new ASN1OutputStream(null, stream).writeObject(value)

    then:
    stream.toByteArray() == bytes as byte[]

    where:
    value                                    | bytes
    new ASN1ObjectIdentifier("2.5.4.3") | [0x06, 0x03, 0x55, 0x04, 0x03]
    new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.20") | [0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14]
    new ASN1ObjectIdentifier("1.2.840.113549.1.7.2") | [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]
  }

}
