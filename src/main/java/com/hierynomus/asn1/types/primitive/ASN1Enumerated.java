package com.hierynomus.asn1.types.primitive;

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.types.ASN1Tag;

import java.math.BigInteger;

public class ASN1Enumerated extends ASN1PrimitiveValue {
    private final int value;

    private ASN1Enumerated(ASN1Tag tag, int value, byte[] valueBytes) {
        super(tag, valueBytes);
        this.value = value;
    }

    @Override
    public Object getValue() {
        return value;
    }

    public static class Parser implements ASN1Parser<ASN1Enumerated> {
        @Override
        public ASN1Enumerated parse(byte[] value) throws ASN1ParseException {
            ASN1Integer parse = new ASN1Integer.Parser().parse(value);
            BigInteger value1 = (BigInteger) parse.getValue();
            return new ASN1Enumerated(ASN1Tag.ENUMERATED, value1.intValue(), value);
        }
    }
}
