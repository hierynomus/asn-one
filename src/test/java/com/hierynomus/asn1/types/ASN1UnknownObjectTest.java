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
package com.hierynomus.asn1.types;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import com.hierynomus.asn1.types.primitive.ASN1Null;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1UnknownObjectTest {

    static Stream<Arguments> unknownUniversalObjects() {
        return Stream.of(
            arguments("BMPString 'A€'", 30, ASN1Encoding.PRIMITIVE, bytes(0x1e, 0x04, 0x00, 0x41, 0x20, 0xac)),
            arguments("VisibleString 'hi'", 26, ASN1Encoding.PRIMITIVE, bytes(0x1a, 0x02, 'h', 'i')),
            arguments("T61String 'x'", 20, ASN1Encoding.PRIMITIVE, bytes(0x14, 0x01, 'x')),
            arguments("REAL 0", 9, ASN1Encoding.PRIMITIVE, bytes(0x09, 0x00)),
            arguments("RELATIVE-OID 1.2", 13, ASN1Encoding.PRIMITIVE, bytes(0x0d, 0x02, 0x01, 0x02)),
            arguments("EXTERNAL (constructed)", 8, ASN1Encoding.CONSTRUCTED, bytes(0x28, 0x03, 0x02, 0x01, 0x05)),
            arguments("high tag number 36 (DATE-TIME)", 36, ASN1Encoding.PRIMITIVE, bytes(0x1f, 0x24, 0x01, 0x00)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unknownUniversalObjects")
    void shouldKeepUnknownUniversalObjectAndReEncodeIt(String description, int tagNumber, ASN1Encoding encoding, byte[] encoded) throws IOException {
        ASN1Object<?> object = new ASN1InputStream(BERDecoder.lenient(), encoded).readObject();

        ASN1UnknownObject unknown = assertInstanceOf(ASN1UnknownObject.class, object);
        assertEquals(ASN1TagClass.UNIVERSAL, unknown.getTag().getAsn1TagClass());
        assertEquals(tagNumber, unknown.getTag().getTag());
        assertEquals(encoding, unknown.getTag().getAsn1Encoding());
        assertArrayEquals(encoded, write(unknown));
    }

    @Test
    void shouldExposeContentsOfConstructedUnknownObjectForFurtherParsing() {
        ASN1UnknownObject unknown = new ASN1InputStream(BERDecoder.lenient(), bytes(0x28, 0x03, 0x02, 0x01, 0x05)).readObject();

        ASN1Object<?> nested = new ASN1InputStream(BERDecoder.lenient(), unknown.getValue()).readObject();

        assertEquals(new ASN1Integer(5), nested);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unknownUniversalObjects")
    void shouldRejectUnknownUniversalObjectByDefault(String description, int tagNumber, ASN1Encoding encoding, byte[] encoded) {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);

        assertEquals("Unknown ASN.1 tag 'UNIVERSAL:" + tagNumber + "' found", ex.getMessage());
    }

    @Test
    void shouldSupportLenientDERDecoder() {
        ASN1Object<?> object = new ASN1InputStream(DERDecoder.lenient(), bytes(0x1e, 0x02, 0x00, 0x41)).readObject();

        assertInstanceOf(ASN1UnknownObject.class, object);
        assertFalse(new DERDecoder().isLenient());
        assertTrue(DERDecoder.lenient().isLenient());
    }

    @Test
    void shouldApplyDecoderSettingToLazilyParsedTaggedObject() {
        // [0] EXPLICIT BMPString "A": the contents of a tagged object are only parsed on getObject()
        byte[] encoded = bytes(0xa0, 0x04, 0x1e, 0x02, 0x00, 0x41);

        ASN1TaggedObject lenient = new ASN1InputStream(BERDecoder.lenient(), encoded).readObject();
        ASN1TaggedObject strict = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertInstanceOf(ASN1UnknownObject.class, lenient.getObject());
        assertThrows(ASN1ParseException.class, strict::getObject);
    }

    @Test
    void forTagShouldStillRejectUnknownUniversalTag() {
        assertThrows(ASN1ParseException.class, () -> ASN1Tag.forTag(ASN1TagClass.UNIVERSAL, 30));
        assertEquals(ASN1Tag.INTEGER, ASN1Tag.forTagOrUnknown(ASN1TagClass.UNIVERSAL, 2));
    }

    @Test
    void shouldRejectConstructedUnknownObjectWithMalformedContents() {
        // [UNIVERSAL 8] constructed, but its contents are not a complete encoding (length 5, only 1 byte)
        ASN1InputStream is = new ASN1InputStream(BERDecoder.lenient(), bytes(0x28, 0x03, 0x02, 0x05, 0x01));

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    @Test
    void shouldRejectTextThatIsNotBerEncoded() {
        // E.g. a PEM certificate passed in without Base64 decoding: '-' (0x2D) reads as a constructed UNIVERSAL 13
        byte[] pem = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ...\n-----END CERTIFICATE-----\n".getBytes(StandardCharsets.US_ASCII);

        assertThrows(ASN1ParseException.class, () -> new ASN1InputStream(BERDecoder.lenient(), pem).readObject());
        assertThrows(ASN1ParseException.class, () -> new ASN1InputStream(new BERDecoder(), pem).readObject());
    }

    @Test
    void shouldParseRestOfStructureAroundUnknownObject() throws IOException {
        // SEQUENCE { INTEGER 1, BMPString "A", NULL }
        byte[] encoded = bytes(0x30, 0x09, 0x02, 0x01, 0x01, 0x1e, 0x02, 0x00, 0x41, 0x05, 0x00);

        ASN1Sequence sequence = new ASN1InputStream(BERDecoder.lenient(), encoded).readObject();

        assertEquals(3, sequence.size());
        assertEquals(new ASN1Integer(1), sequence.get(0));
        assertArrayEquals(bytes(0x00, 0x41), assertInstanceOf(ASN1UnknownObject.class, sequence.get(1)).getValue());
        assertEquals(new ASN1Null(), sequence.get(2));
        assertArrayEquals(encoded, write(new ASN1Sequence(sequence.getValue())));
    }

    @Test
    void shouldCompareByTagAndContents() {
        ASN1UnknownObject bmp = new ASN1UnknownObject(ASN1Tag.forTagOrUnknown(ASN1TagClass.UNIVERSAL, 30), bytes(0x00, 0x41));

        assertEquals(bmp, new ASN1InputStream(BERDecoder.lenient(), bytes(0x1e, 0x02, 0x00, 0x41)).readObject());
        assertNotEquals(bmp, new ASN1UnknownObject(ASN1Tag.forTagOrUnknown(ASN1TagClass.UNIVERSAL, 30), bytes(0x00, 0x42)));
        assertNotEquals(bmp, new ASN1UnknownObject(ASN1Tag.forTagOrUnknown(ASN1TagClass.UNIVERSAL, 26), bytes(0x00, 0x41)));
    }

    @Test
    void shouldIncludeTagAndContentsInToString() {
        ASN1UnknownObject bmp = new ASN1UnknownObject(ASN1Tag.forTagOrUnknown(ASN1TagClass.UNIVERSAL, 30), bytes(0x00, 0x41));

        assertEquals("ASN1UnknownObject[ASN1Tag[UNIVERSAL,PRIMITIVE,30],0041]", bmp.toString());
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
