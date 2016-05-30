package com.hierynomus.asn1

import spock.lang.Specification

class ASN1InputStreamSpec extends Specification {

  def "does not support indefinite length encoding"() {
    given:
    def is = new ASN1InputStream([0x01, 0x80, 0x01] as byte[])

    when:
    is.readObject()

    then:
    def ex = thrown(ASN1ParseException.class)
    ex.getMessage() == "The indefinite length form is not (yet) supported!"
  }
}
