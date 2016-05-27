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

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier
import com.hierynomus.asn1.types.constructed.ASN1Sequence
import com.hierynomus.asn1.types.ASN1Tag
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject
import spock.lang.Specification

class IntegrationSpec extends Specification {

  def "should parse a NegTokenInit response (NTLM)"() {
    given:
    def stream = new ASN1InputStream([0x60, 0x28, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x1E, 0x30, 0x1C, 0xA0, 0x1A, 0x30, 0x18, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A] as byte[])

    expect:
    ASN1TaggedObject object = stream.readObject()
    ASN1Sequence seq = object.getObject(ASN1Tag.SEQUENCE)
    seq.size() == 2
    seq.get(0) == new ASN1ObjectIdentifier("1.3.6.1.5.5.2")
    seq.get(1) instanceof ASN1TaggedObject
    ASN1Sequence seq2 = seq.get(1).getValue()
    seq2.size() == 1
    seq2.get(0) instanceof ASN1TaggedObject
    ASN1Sequence seq3 = seq2.get(0).getValue()
    seq3.size() == 2
    seq3.get(0) == new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.30")
    seq3.get(1) == new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10")
  }
}
