package com.hierynomus.asn1.encodingrules;

import com.hierynomus.asn1.ASN1Decoder;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

public class ASN1TagParserFactory {

    private ASN1Decoder decoder;

    public ASN1TagParserFactory(final ASN1Decoder decoder) {
        this.decoder = decoder;
    }

    public <T extends ASN1Object> ASN1Parser<T> newParser(ASN1Tag<T> tag) {
        switch (tag.getAsn1TagClass()) {
            case Universal:
                return newUniversalParser(tag);
                break;
            case Application:
                break;
            case ContextSpecific:
                break;
            case Private:
                break;
        }
    }

    private <T extends ASN1Object> ASN1Parser<T> newUniversalParser(final ASN1Tag<T> tag) {
        if (tag.equals(ASN1Tag.BOOLEAN)) {
            return (ASN1Parser<T>) decoder.newBooleanParser();
        } else if (tag.equals(ASN1Tag.INTEGER)) {
            return
        }
    }
}
