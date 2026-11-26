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
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.asn1.types.string.ASN1GeneralizedTime;
import com.hierynomus.asn1.types.string.ASN1IA5String;
import com.hierynomus.asn1.types.string.ASN1UTCTime;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Parses X.509 certificates generated with OpenSSL (see #5). Structure per RFC 5280 4.1:
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer, validity, subject, ... }
 */
class X509CertificateTest {

    private static final ASN1ObjectIdentifier EMAIL_ADDRESS = new ASN1ObjectIdentifier("1.2.840.113549.1.9.1");

    @Test
    void shouldParseCertificateWithEmailAddress() throws IOException {
        ASN1Sequence tbsCertificate = tbsCertificate("rsa-email.der");

        ASN1Sequence validity = (ASN1Sequence) tbsCertificate.get(4);
        assertEquals(Date.from(Instant.parse("2025-01-01T00:00:00Z")), assertInstanceOf(ASN1UTCTime.class, validity.get(0)).getDate());
        assertEquals(Date.from(Instant.parse("2026-01-01T00:00:00Z")), assertInstanceOf(ASN1UTCTime.class, validity.get(1)).getDate());

        ASN1IA5String email = null;
        for (ASN1Object rdn : (ASN1Sequence) tbsCertificate.get(5)) {
            for (ASN1Object attribute : ((ASN1Set) rdn).getValue()) {
                ASN1Sequence typeAndValue = (ASN1Sequence) attribute;
                if (EMAIL_ADDRESS.equals(typeAndValue.get(0))) {
                    email = assertInstanceOf(ASN1IA5String.class, typeAndValue.get(1));
                }
            }
        }
        assertNotNull(email, "subject should contain an emailAddress");
        assertEquals("admin@example.com", email.getValue());
    }

    @Test
    void shouldParseCertificateValidBeyond2049() throws IOException {
        ASN1Sequence tbsCertificate = tbsCertificate("ec-generalizedtime.der");

        // RFC 5280 4.1.2.5: dates through 2049 as UTCTime, from 2050 on as GeneralizedTime
        ASN1Sequence validity = (ASN1Sequence) tbsCertificate.get(4);
        assertEquals(Date.from(Instant.parse("2025-01-01T00:00:00Z")), assertInstanceOf(ASN1UTCTime.class, validity.get(0)).getDate());
        assertEquals(Date.from(Instant.parse("2052-01-01T00:00:00Z")), assertInstanceOf(ASN1GeneralizedTime.class, validity.get(1)).getDate());
    }

    private static ASN1Sequence tbsCertificate(String resource) throws IOException {
        try (InputStream is = X509CertificateTest.class.getResourceAsStream("/certificates/" + resource)) {
            ASN1Sequence certificate = new ASN1InputStream(new BERDecoder(), is.readAllBytes()).readObject();
            assertEquals(3, certificate.size());
            return (ASN1Sequence) certificate.get(0);
        }
    }
}
