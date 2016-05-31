package com.hierynomus.asn1.encodingrules;

import com.hierynomus.asn1.types.ASN1Tag;

import java.io.InputStream;

public interface ASN1Decoder {

    ASN1Tag<?> readTag(InputStream is);

    int readLength(InputStream is);

    byte[] readValue(int length, InputStream is);
}
