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
package com.hierynomus.asn1.types.constructed;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static com.hierynomus.asn1.types.ASN1Tag.application;
import static com.hierynomus.asn1.types.ASN1Tag.contextSpecific;
import static com.hierynomus.asn1.types.ASN1TagClass.APPLICATION;
import static com.hierynomus.asn1.types.ASN1TagClass.CONTEXT_SPECIFIC;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1TaggedObjectTest {

    private static final ASN1ObjectIdentifier SPNEGO_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.2");

    static Stream<Arguments> explicitTaggedObjects() {
        return Stream.of(
            arguments(bytes(0x60, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), ASN1Tag.forTag(APPLICATION, 0x0).constructed()),
            arguments(bytes(0xa1, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), ASN1Tag.forTag(CONTEXT_SPECIFIC, 0x01).constructed()));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("explicitTaggedObjects")
    void shouldParseExplicitTaggedObject(byte[] encoded, ASN1Tag<?> tag) {
        ASN1TaggedObject taggedObject = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(tag, taggedObject.getTag());
        assertEquals(SPNEGO_OID, taggedObject.getObject());
    }

    static Stream<Arguments> implicitTaggedObjects() {
        return Stream.of(
            arguments(bytes(0x40, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), ASN1Tag.forTag(APPLICATION, 0x0).primitive()),
            arguments(bytes(0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), ASN1Tag.forTag(CONTEXT_SPECIFIC, 0x01).primitive()));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("implicitTaggedObjects")
    void shouldParseImplicitTaggedObject(byte[] encoded, ASN1Tag<?> tag) {
        ASN1TaggedObject taggedObject = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(tag, taggedObject.getTag());
        assertEquals(SPNEGO_OID, taggedObject.getObject(ASN1Tag.OBJECT_IDENTIFIER));
    }

    @Test
    void shouldNotParseImplicitTaggedObjectAsExplicit() {
        ASN1TaggedObject taggedObject = new ASN1InputStream(new BERDecoder(), bytes(0x60, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02)).readObject();

        assertThrows(ASN1ParseException.class, taggedObject::getObject);
    }

    static Stream<Arguments> taggedObjectsToWrite() {
        return Stream.of(
            arguments(new ASN1TaggedObject(application(0x0).primitive(), SPNEGO_OID, false), bytes(0x40, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02)),
            arguments(new ASN1TaggedObject(application(0x0).constructed(), SPNEGO_OID), bytes(0x60, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02)),
            arguments(new ASN1TaggedObject(contextSpecific(0x01).primitive(), SPNEGO_OID, false), bytes(0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02)),
            arguments(new ASN1TaggedObject(contextSpecific(0x01).constructed(), SPNEGO_OID), bytes(0xa1, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("taggedObjectsToWrite")
    void shouldWriteTaggedObject(ASN1Object<?> value, byte[] expected) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        new ASN1OutputStream(new DEREncoder(), baos).writeObject(value);

        assertArrayEquals(expected, baos.toByteArray());
    }
}
