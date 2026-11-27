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
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static com.hierynomus.asn1.types.ASN1Tag.application;
import static com.hierynomus.asn1.types.ASN1Tag.contextSpecific;
import static com.hierynomus.asn1.types.ASN1TagClass.APPLICATION;
import static com.hierynomus.asn1.types.ASN1TagClass.CONTEXT_SPECIFIC;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    private static ASN1TaggedObject read(byte[] encoded) {
        return new ASN1InputStream(new BERDecoder(), encoded).readObject();
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("implicitTaggedObjects")
    void primitiveParsedTaggedObjectShouldBeImplicit(byte[] encoded, ASN1Tag<?> tag) {
        assertFalse(read(encoded).isExplicit());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("explicitTaggedObjects")
    void constructedParsedTaggedObjectMayBeExplicit(byte[] encoded, ASN1Tag<?> tag) {
        assertTrue(read(encoded).isExplicit());
    }

    @Test
    void shouldNotReadPrimitiveTaggedObjectAsExplicit() {
        // [1] IMPLICIT OCTET STRING whose contents happen to be a valid encoding (02 01 05, INTEGER 5): X.690 8.14.2
        // requires an explicit tag to be constructed, so this must not be decoded as an explicitly tagged INTEGER.
        ASN1TaggedObject taggedObject = read(bytes(0x81, 0x03, 0x02, 0x01, 0x05));

        assertThrows(ASN1ParseException.class, taggedObject::getObject);
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("implicitTaggedObjects")
    void parsedImplicitTaggedObjectsShouldBeComparable(byte[] encoded, ASN1Tag<?> tag) {
        assertEquals(read(encoded), read(encoded));
        assertEquals(read(encoded).hashCode(), read(encoded).hashCode());
    }

    @Test
    void parsedTaggedObjectsWithDifferentContentsShouldNotBeEqual() {
        assertNotEquals(read(bytes(0x81, 0x01, 0x05)), read(bytes(0x81, 0x01, 0x06)));
        assertNotEquals(read(bytes(0x81, 0x01, 0x05)), read(bytes(0x82, 0x01, 0x05)));
    }

    static Stream<Arguments> parsedAndConstructed() {
        return Stream.of(
            arguments(bytes(0x81, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), new ASN1TaggedObject(contextSpecific(0x01).primitive(), SPNEGO_OID, false)),
            arguments(bytes(0xa1, 0x08, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02), new ASN1TaggedObject(contextSpecific(0x01).constructed(), SPNEGO_OID)),
            arguments(bytes(0xa1, 0x03, 0x02, 0x01, 0x05), new ASN1TaggedObject(contextSpecific(0x01).constructed(), new ASN1Sequence(Collections.<ASN1Object>singletonList(new ASN1Integer(5))), false)));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("parsedAndConstructed")
    void parsedTaggedObjectShouldEqualConstructedOne(byte[] encoded, ASN1TaggedObject constructed) {
        ASN1TaggedObject parsed = read(encoded);

        assertEquals(constructed, parsed);
        assertEquals(parsed, constructed);
        assertEquals(constructed.hashCode(), parsed.hashCode());
    }

    @Test
    void parsedTaggedObjectShouldNotEqualConstructedOneThatDoesNotMatch() {
        ASN1TaggedObject parsed = read(bytes(0xa1, 0x03, 0x02, 0x01, 0x05));

        assertNotEquals(new ASN1TaggedObject(contextSpecific(0x01).constructed(), new ASN1Integer(6)), parsed);
        // The contents are not an OBJECT IDENTIFIER, so decoding fails: not equal rather than an exception
        assertNotEquals(new ASN1TaggedObject(contextSpecific(0x01).constructed(), SPNEGO_OID), parsed);
    }
}
