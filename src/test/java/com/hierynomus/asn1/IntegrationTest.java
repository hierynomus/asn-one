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
package com.hierynomus.asn1;

import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1BitString;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.BitSet;
import java.util.List;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class IntegrationTest {

    // GSS-API NegTokenInit (SPNEGO) offering NEGOEX and NTLMSSP
    private static final byte[] NEG_TOKEN_INIT = bytes(
        0x60, 0x28, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x1E, 0x30, 0x1C, 0xA0, 0x1A, 0x30, 0x18,
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
        0x01, 0x82, 0x37, 0x02, 0x02, 0x0A);

    @Test
    void shouldParseNegTokenInit() {
        ASN1InputStream stream = new ASN1InputStream(new BERDecoder(), NEG_TOKEN_INIT);

        ASN1TaggedObject object = stream.readObject();
        ASN1Sequence seq = object.getObject(ASN1Tag.SEQUENCE);
        assertEquals(2, seq.size());
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.2"), seq.get(0));

        ASN1Sequence seq2 = (ASN1Sequence) assertInstanceOf(ASN1TaggedObject.class, seq.get(1)).getValue();
        assertEquals(1, seq2.size());

        ASN1Sequence seq3 = (ASN1Sequence) assertInstanceOf(ASN1TaggedObject.class, seq2.get(0)).getValue();
        assertEquals(2, seq3.size());
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.30"), seq3.get(0));
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10"), seq3.get(1));
    }

    @Test
    void shouldConstructNegTokenInit() throws IOException {
        ASN1BitString contextFlags = new ASN1BitString(BitSet.valueOf(bytes(0x03)));
        ASN1Sequence mechTypes = new ASN1Sequence(Arrays.<ASN1Object>asList(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.30"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.2.2.10")));
        ASN1Sequence negTokenInit = new ASN1Sequence(Arrays.<ASN1Object>asList(
            new ASN1TaggedObject(ASN1Tag.contextSpecific(0).constructed(), mechTypes),
            new ASN1TaggedObject(ASN1Tag.contextSpecific(1).constructed(), contextFlags)));
        ASN1Sequence implicitSeq = new ASN1Sequence(Arrays.<ASN1Object>asList(
            new ASN1ObjectIdentifier("1.3.6.1.5.5.2"),
            new ASN1TaggedObject(ASN1Tag.contextSpecific(0).constructed(), negTokenInit)));
        ASN1TaggedObject gssApi = new ASN1TaggedObject(ASN1Tag.application(0).constructed(), implicitSeq, false);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        new ASN1OutputStream(new DEREncoder(), baos).writeObject(gssApi);

        // Round-trip: the serialized form must parse back into the same structure.
        ASN1TaggedObject parsed = new ASN1InputStream(new BERDecoder(), baos.toByteArray()).readObject();
        assertEquals(gssApi.getTag(), parsed.getTag());
        ASN1Sequence parsedSeq = parsed.getObject(ASN1Tag.SEQUENCE);
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.2"), parsedSeq.get(0));
        ASN1Sequence parsedNegTokenInit = (ASN1Sequence) ((ASN1TaggedObject) parsedSeq.get(1)).getObject();
        assertEquals(mechTypes, ((ASN1TaggedObject) parsedNegTokenInit.get(0)).getObject());
        ASN1BitString parsedFlags = (ASN1BitString) ((ASN1TaggedObject) parsedNegTokenInit.get(1)).getObject();
        assertArrayEquals(contextFlags.getValue(), parsedFlags.getValue());
    }

    @Test
    void shouldCorrectlyParseHigherNumberTaggedValues() {
        String b64 = "MIGwoQgxBgIBAgIBA6IDAgEBowQCAggApQUxAwIBBKYIMQYCAQMCAQW/gUgFAgMBAAG/g3cCBQC/hT4DAgEAv4VATDBKBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQgco2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1NVCDUpCEqTeAG/hUEDAgEAv4VCBQIDAxSzv4VOBgIEATQV8b+FTwYCBAE0Few=";
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), Base64.getDecoder().decode(b64));

        ASN1Sequence s = is.readObject();

        List<Integer> expectedTags = Arrays.asList(1, 2, 3, 5, 6, 200, 503, 702, 704, 705, 706, 718, 719);
        assertEquals(expectedTags.size(), s.size());
        for (int i = 0; i < expectedTags.size(); i++) {
            assertEquals(expectedTags.get(i), s.get(i).getTag().getTag(), "tag number of element " + i);
        }
    }
}
