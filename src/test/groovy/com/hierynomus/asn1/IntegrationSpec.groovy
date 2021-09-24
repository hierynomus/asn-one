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
import com.hierynomus.asn1.encodingrules.der.DERDecoder
import com.hierynomus.asn1.encodingrules.der.DEREncoder
import com.hierynomus.asn1.types.constructed.ASN1SetSpec
import com.hierynomus.asn1.types.constructed.ASN1TaggedObjectSpec
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier
import com.hierynomus.asn1.types.constructed.ASN1Sequence
import com.hierynomus.asn1.types.ASN1Tag
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject
import com.hierynomus.asn1.types.string.ASN1BitString
import spock.lang.Specification

import javax.xml.bind.DatatypeConverter

class IntegrationSpec extends Specification {

  def "should parse a NegTokenInit response (NTLM)"() {
    given:
    def stream = new ASN1InputStream(new BERDecoder(), [0x60, 0x28, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x1E, 0x30, 0x1C, 0xA0, 0x1A, 0x30, 0x18, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A] as byte[])

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

  def "should construct a NegTokenInit (NTLM)"() {
    given:
    def contextFlags = new ASN1BitString(BitSet.valueOf([0x03] as byte[]))
    def mechListMic = new ASN1Sequence([new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.30"), new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10")])
    def negTokenInit = new ASN1Sequence([new ASN1TaggedObject(ASN1Tag.contextSpecific(0).constructed(), mechListMic), new ASN1TaggedObject(ASN1Tag.contextSpecific(1).constructed(), contextFlags)])
    def implictSeq = new ASN1Sequence([new ASN1ObjectIdentifier("1.3.6.1.5.5.2"), new ASN1TaggedObject(ASN1Tag.contextSpecific(0).constructed(), negTokenInit)])
    def gssApi = new ASN1TaggedObject(ASN1Tag.application(0).constructed(), implictSeq, false)
    def stream = new ByteArrayOutputStream()

    when:
    new ASN1OutputStream(new DEREncoder(), stream).writeObject(gssApi)

    then:
    println(DatatypeConverter.printHexBinary(stream.toByteArray()))
  }


  def "Should correctly parse higher number tagged values"() {
    given:
    def b64 = "MIGwoQgxBgIBAgIBA6IDAgEBowQCAggApQUxAwIBBKYIMQYCAQMCAQW/gUgFAgMBAAG/g3cCBQC/hT4DAgEAv4VATDBKBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQgco2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1NVCDUpCEqTeAG/hUEDAgEAv4VCBQIDAxSzv4VOBgIEATQV8b+FTwYCBAE0Few="

    when:
    def is = new ASN1InputStream(new BERDecoder(), b64.decodeBase64() as byte[])

    then:
    ASN1Sequence s = is.readObject()
    s.size() == 13
    s.get(0).tag.tag == 1
    s.get(1).tag.tag == 2
    s.get(2).tag.tag == 3
    s.get(3).tag.tag == 5
    s.get(4).tag.tag == 6
    s.get(5).tag.tag == 200
    s.get(6).tag.tag == 503
    s.get(7).tag.tag == 702
    s.get(8).tag.tag == 704
    s.get(9).tag.tag == 705
    s.get(10).tag.tag == 706
    s.get(11).tag.tag == 718
    s.get(12).tag.tag == 719

  }
}
