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
import com.hierynomus.asn1.ASN1ParseException
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier
import spock.lang.Specification
import spock.lang.Unroll

import static com.hierynomus.asn1.types.ASN1Tag.ASN1TagClass.Application
import static com.hierynomus.asn1.types.ASN1Tag.ASN1TagClass.ContextSpecific

@Unroll
class ASN1TaggedObjectSpec extends Specification {

  def "should parse an explicit ASN.1 Tagged Object #tag"() {
    given:
    def is = new ASN1InputStream(new ByteArrayInputStream(bytes as byte[]))
    def taggedObject = is.readObject()

    expect:
    taggedObject.tag == tag
    (taggedObject as ASN1TaggedObject).getObject() == object

    where:
    bytes                                                        | tag                                   | object
    [0x60, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(Application, 0x0)      | new ASN1ObjectIdentifier("1.3.6.1.5.5.2")
    [0x81, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(ContextSpecific, 0x01) | new ASN1ObjectIdentifier("1.3.6.1.5.5.2")
  }

  def "should parse an implicit ASN.1 Tagged Object #tag"() {
    given:
    def is = new ASN1InputStream(new ByteArrayInputStream(bytes as byte[]))
    def taggedObject = is.readObject()

    expect:
    taggedObject.tag == tag
    (taggedObject as ASN1TaggedObject).getObject(ASN1Tag.OBJECT_IDENTIFIER) == object

    where:
    bytes                                            | tag                                   | object
    [0x60, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(Application, 0x0)      | new ASN1ObjectIdentifier("1.3.6.1.5.5.2")
    [0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(ContextSpecific, 0x01) | new ASN1ObjectIdentifier("1.3.6.1.5.5.2")
  }

  def "should not parse an implicit ASN.1 Tagged Object with as explicit"() {
    given:
    def is = new ASN1InputStream(new ByteArrayInputStream([0x60, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] as byte[]))
    def taggedObject = is.readObject()

    when:
    (taggedObject as ASN1TaggedObject).getObject()

    then:
    thrown(ASN1ParseException.class)
  }
}
