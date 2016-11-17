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

import com.hierynomus.asn1.ASN1InputStream
import com.hierynomus.asn1.ASN1OutputStream
import com.hierynomus.asn1.ASN1ParseException
import com.hierynomus.asn1.encodingrules.ber.BERDecoder
import com.hierynomus.asn1.encodingrules.der.DEREncoder
import com.hierynomus.asn1.types.ASN1Tag
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier
import spock.lang.Specification
import spock.lang.Unroll

import static com.hierynomus.asn1.types.ASN1Tag.application
import static com.hierynomus.asn1.types.ASN1Tag.contextSpecific
import static com.hierynomus.asn1.types.ASN1TagClass.Application
import static com.hierynomus.asn1.types.ASN1TagClass.ContextSpecific

@Unroll
class ASN1TaggedObjectSpec extends Specification {


  public static final ASN1ObjectIdentifier SPNEGO_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.2")

  def "should parse an explicit ASN.1 Tagged Object #tag"() {
    given:
    def is = new ASN1InputStream(new BERDecoder(), new ByteArrayInputStream(bytes as byte[]))
    def taggedObject = is.readObject()

    expect:
    taggedObject.tag == tag
    (taggedObject as ASN1TaggedObject).getObject() == object

    where:
    bytes                                                        | tag                                   | object
    [0x60, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(Application, 0x0).constructed()      | SPNEGO_OID
    [0xa1, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(ContextSpecific, 0x01).constructed() | SPNEGO_OID
  }

  def "should parse an implicit ASN.1 Tagged Object #tag"() {
    given:
    def is = new ASN1InputStream(new BERDecoder(), new ByteArrayInputStream(bytes as byte[]))
    def taggedObject = is.readObject()

    expect:
    taggedObject.tag == tag
    (taggedObject as ASN1TaggedObject).getObject(ASN1Tag.OBJECT_IDENTIFIER) == object

    where:
    bytes                                            | tag                                   | object
    [0x40, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(Application, 0x0).primitive()      | SPNEGO_OID
    [0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] | ASN1Tag.forTag(ContextSpecific, 0x01).primitive() | SPNEGO_OID
  }

  def "should not parse an implicit ASN.1 Tagged Object with as explicit"() {
    given:
    def is = new ASN1InputStream(new BERDecoder(), new ByteArrayInputStream([0x60, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02] as byte[]))
    def taggedObject = is.readObject()

    when:
    (taggedObject as ASN1TaggedObject).getObject()

    then:
    thrown(ASN1ParseException.class)
  }

  def "should write an ASN.1 #tagging Tagged Object (#tag)"() {
    given:
    def baos = new ByteArrayOutputStream()

    when:
    new ASN1OutputStream(new DEREncoder(), baos).writeObject(value)

    then:
    baos.toByteArray() == bytes as byte[]

    where:
    value | bytes
    new ASN1TaggedObject(application(0x0).primitive(), SPNEGO_OID, false) | [0x40, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]
    new ASN1TaggedObject(application(0x0).constructed(), SPNEGO_OID) | [0x60, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]
    new ASN1TaggedObject(contextSpecific(0x01).primitive(), SPNEGO_OID, false) | [0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]
    new ASN1TaggedObject(contextSpecific(0x01).constructed(), SPNEGO_OID) | [0xa1, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02]

    tagging = value.explicit ? "explicit" : "implicit"
    tag = value.tag
  }
}
