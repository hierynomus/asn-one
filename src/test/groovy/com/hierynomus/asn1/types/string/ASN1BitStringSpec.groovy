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
package com.hierynomus.asn1.types.string

import com.hierynomus.asn1.ASN1InputStream
import com.hierynomus.asn1.ASN1OutputStream
import com.hierynomus.asn1.encodingrules.ber.BERDecoder
import com.hierynomus.asn1.encodingrules.der.DEREncoder
import com.hierynomus.asn1.types.ASN1Encoding
import spock.lang.Specification
import spock.lang.Unroll

class ASN1BitStringSpec extends Specification {

  @Unroll
  def "should parse an ASN.1 BIT STRING"() {
    given:
    def object = new ASN1InputStream(new BERDecoder(), bytes as byte[]).readObject()

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
    [0x03, 0x04, 0x06, 0x6E, 0x5D, 0xC0] | 18     | [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]
  }

  @Unroll
  def "should deserialize an ASN.1 BIT STRING and reconstruct it from the returned value"() {
    given:
    def object = new ASN1InputStream(new BERDecoder(), bytes as byte[]).readObject()

    expect:
    object instanceof ASN1BitString

    with(object as ASN1BitString) { ASN1BitString bs ->
      def bitString2 = new ASN1BitString(bs.getValue())
      bitString2.length() == length
      (0..length - 1).every {
        bs.isSet(it) == bitString2.isSet(it)
      }
    }

    where:
    bytes                                | length | values
    [0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4] | 22     | [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1]
    [0x03, 0x04, 0x06, 0x6E, 0x5D, 0xC0] | 18     | [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]
  }
//
//  def "should construct ASN.1 BIT STRING correctly from boolean[]"() {
//    given:
//    def bits = bitValues.collect { b -> b == 1 } as boolean[]
//    def bitString = new ASN1BitString(bits)
//    print(bitString)
//
//    expect:
//    bitValues.eachWithIndex { int entry, int idx ->
//      bitString.isSet(idx) == (entry == 1)
//    }
//
//    where:
//    bitValues << [[1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1],
//    [0,1,1,0,1,1,1,0,0,1,0,1,1,1,0,1,1,1]]
//  }

  @Unroll
  def "should construct ASN.1 BIT STRING correctly from #sourceType with length #valueLength"() {
    given:
    def bitString = new ASN1BitString(convert(bitValues))

    expect:
    bitValues.eachWithIndex { int entry, int idx ->
      bitString.isSet(idx) == (entry == 1)
    }

    where:
    bitValues                                                          | convert          | sourceType
    [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1] | this.&toBitSet   | "BitSet"
    [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]             | this.&toBitSet   | "BitSet"
    [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1] | this.&toBooleans | "boolean[]"
    [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]             | this.&toBooleans | "boolean[]"

    valueLength = bitValues.size()
  }

  @Unroll
  def "should serialize ASN.1 BIT STRING from #sourceType with length #valueLength"() {
    given:
    def baos = new ByteArrayOutputStream()
    def os = new ASN1OutputStream(new DEREncoder(), baos)
    def bitString = new ASN1BitString(convert(bitValues))

    when:
    os.writeObject(bitString)

    then:
    baos.toByteArray() == bytes as byte[]

    where:
    bitValues                                                          | convert          | sourceType  | bytes
    [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1] | this.&toBooleans | "boolean[]" | [0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4]
    [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]             | this.&toBooleans | "boolean[]" | [0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0]
    [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1] | this.&toBitSet   | "BitSet"    | [0x03, 0x04, 0x00, 0xF0, 0xF0, 0xF4]
    [0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1]             | this.&toBitSet   | "BitSet"    | [0x03, 0x04, 0x00, 0x6e, 0x5d, 0xc0]

    valueLength = bitValues.size()
  }

  def "should retain knowledge that the ASN.1 BIT STRING was in Constructed Encoding"() {
    given:
    def is = new ASN1InputStream(new BERDecoder(), [0x23, 0x09, 0x03, 0x03, 0x0, 0xF0, 0xF0, 0x03, 0x02, 0x02, 0xF4] as byte[])

    when:
    def object = is.readObject()

    then:
    object.getTag().getAsn1Encoding() == ASN1Encoding.Constructed
    (object as ASN1BitString).length() == 22
  }

  def toBooleans(bitValues) {
    return bitValues.collect { b -> b == 1 } as boolean[]
  }

  def toBitSet(bitValues) {
    return new BitSet().with {
      bitValues.eachWithIndex { int entry, int idx ->
        it.set(idx, entry ? true : false)
      }
      it
    }
  }
}
