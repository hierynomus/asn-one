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
import com.hierynomus.asn1.ASN1ParseException
import spock.lang.Specification
import spock.lang.Unroll

class ASN1IntegerSpec extends Specification {
  static def LARGE_INT = [0x02, 0x81, 0x81, 0x00,
                          0x8f, 0xe2, 0x41, 0x2a, 0x08, 0xe8, 0x51, 0xa8, 0x8c, 0xb3, 0xe8, 0x53, 0xe7, 0xd5, 0x49, 0x50,
                          0xb3, 0x27, 0x8a, 0x2b, 0xcb, 0xea, 0xb5, 0x42, 0x73, 0xea, 0x02, 0x57, 0xcc, 0x65, 0x33, 0xee,
                          0x88, 0x20, 0x61, 0xa1, 0x17, 0x56, 0xc1, 0x24, 0x18, 0xe3, 0xa8, 0x08, 0xd3, 0xbe, 0xd9, 0x31,
                          0xf3, 0x37, 0x0b, 0x94, 0xb8, 0xcc, 0x43, 0x08, 0x0b, 0x70, 0x24, 0xf7, 0x9c, 0xb1, 0x8d, 0x5d,
                          0xd6, 0x6d, 0x82, 0xd0, 0x54, 0x09, 0x84, 0xf8, 0x9f, 0x97, 0x01, 0x75, 0x05, 0x9c, 0x89, 0xd4,
                          0xd5, 0xc9, 0x1e, 0xc9, 0x13, 0xd7, 0x2a, 0x6b, 0x30, 0x91, 0x19, 0xd6, 0xd4, 0x42, 0xe0, 0xc4,
                          0x9d, 0x7c, 0x92, 0x71, 0xe1, 0xb2, 0x2f, 0x5c, 0x8d, 0xee, 0xf0, 0xf1, 0x17, 0x1e, 0xd2, 0x5f,
                          0x31, 0x5b, 0xb1, 0x9c, 0xbc, 0x20, 0x55, 0xbf, 0x3a, 0x37, 0x42, 0x45, 0x75, 0xdc, 0x90, 0x65]

  static def INT_VAL = "101038645214968213029489864879507742420925199145132483818978980455132582258676381289000109319204510275496178360219909358646064503513889573494768497419381751359787623037449375660247011308028102339473875820259375735204357343091558075960601364303443174344509161224592926325506446708043127306053676664799729848421"

  @Unroll
  def "should parse ASN.1 INTEGER with value #value"() {
    expect:
    new ASN1InputStream(new ByteArrayInputStream(buffer as byte[])).readObject() == value

    where:
    buffer                   | value
    [0x02, 0x01, 0x03]       | new ASN1Integer(new BigInteger(3))
    [0x02, 0x01, 0x7F]       | new ASN1Integer(new BigInteger(127))
    [0x02, 0x01, 0x80]       | new ASN1Integer(new BigInteger(-128))
    [0x02, 0x02, 0x00, 0x80] | new ASN1Integer(new BigInteger(128))
    [0x02, 0x01, 0x83]       | new ASN1Integer(new BigInteger(-125))
    LARGE_INT                | new ASN1Integer(new BigInteger(INT_VAL))
  }

  def "should fail when trying to read an ASN.1 Integer with the 'constructed' bit set"() {
    given:
    def is = new ASN1InputStream([0x22, 0x01, 0x03] as byte[])

    when:
    is.readObject()

    then:
    def ex = thrown(ASN1ParseException.class)
    def wrapped = ex.getCause()
    wrapped.message ==~ "The ASN.1 tag .* does not support encoding as Constructed"
  }

  @Unroll
  def "should write ASN.1 INTEGER #value as bytes #bytes"() {
    given:
    def stream = new ByteArrayOutputStream()

    when:
    new ASN1OutputStream(stream).writeObject(value)

    then:
    stream.toByteArray() == bytes as byte[]

    where:
    value                                    | bytes
    new ASN1Integer(new BigInteger(3))       | [0x02, 0x01, 0x03]
    new ASN1Integer(new BigInteger(127))     | [0x02, 0x01, 0x7F]
    new ASN1Integer(new BigInteger(-128))    | [0x02, 0x01, 0x80]
    new ASN1Integer(new BigInteger(128))     | [0x02, 0x02, 0x00, 0x80]
    new ASN1Integer(new BigInteger(-125))    | [0x02, 0x01, 0x83]
    new ASN1Integer(new BigInteger(INT_VAL)) | LARGE_INT
  }

}
