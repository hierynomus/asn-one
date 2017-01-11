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
package com.hierynomus.asn1.encodingrules.ber;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Decoder;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.types.ASN1Encoding;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1TagClass;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.*;
import com.hierynomus.asn1.types.string.ASN1BitString;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import com.hierynomus.asn1.util.Checks;

import static com.hierynomus.asn1.util.Checks.checkArgument;

public class BERDecoder implements ASN1Decoder {

    @Override
    public ASN1Tag<?> readTag(InputStream is) {
        try {
            int tagByte = is.read();
            ASN1TagClass asn1TagClass = ASN1TagClass.parseClass((byte) tagByte);
            ASN1Encoding asn1Encoding = ASN1Encoding.parseEncoding((byte) tagByte);
            int tag = tagByte & 0x1f;
            if (tag <= 0x1e) {
                return ASN1Tag.forTag(asn1TagClass, tag).asEncoded(asn1Encoding);
            } else {
                int iTag = 0;
                int read = is.read();
                do {
                    iTag <<= 7;
                    iTag |= (read & 0x7f);
                    read = is.read();
                } while ((read & 0x80) > 0);
                return ASN1Tag.forTag(asn1TagClass, iTag).asEncoded(asn1Encoding);
            }
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to parse ASN.1 tag", ioe);
        }
    }

    @Override
    public int readLength(InputStream is) {
        try {
            int firstByte = is.read();
            if (firstByte < 0x7f) {
                return firstByte;
            }
            int nrBytes = firstByte & 0x7f;
            int longLength = 0;
            for (int i = 0; i < nrBytes; i++) {
                longLength = longLength << 8;
                longLength += is.read();
            }

            if (longLength == 0) {
                throw new ASN1ParseException("The indefinite length form is not (yet) supported!");
            }

            return longLength;
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to read the length of the ASN.1 object.", ioe);
        }
    }

    @Override
    public byte[] readValue(int length, InputStream is) {
        try {
            byte[] value = new byte[length];
            int count = 0;
            int read = 0;
            while (count < length && ((read = is.read(value, count, length - count)) != -1)) {
                count += read;
            }
            return value;
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to read the value of the ASN.1 object", ioe);
        }
    }

    ///////////////////////
    // Primitive parsers //
    ///////////////////////

    @Override
    public ASN1Parser<ASN1Boolean> newBooleanParser() {
        return new ASN1Parser<ASN1Boolean>() {
            @Override
            public ASN1Boolean parse(final ASN1Tag<ASN1Boolean> asn1Tag, final byte[] value) throws ASN1ParseException {
                Checks.checkState(value.length == 1, "Value of ASN.1 BOOLEAN should have length 1, but was %s", value.length);
                return new ASN1Boolean(value, value[0] != 0x0);
            }
        };
    }

    @Override
    public ASN1Parser<ASN1Enumerated> newEnumeratedParser() {
        return new ASN1Parser<ASN1Enumerated>() {
            @Override
            public ASN1Enumerated parse(ASN1Tag<ASN1Enumerated> asn1Tag, byte[] value) throws ASN1ParseException {
                BigInteger enumValue = new BigInteger(value);
                return new ASN1Enumerated(enumValue, value);
            }
        };
    }

    @Override
    public ASN1Parser<ASN1Integer> newIntegerParser() {
        return new ASN1Parser<ASN1Integer>() {
            @Override
            public ASN1Integer parse(ASN1Tag<ASN1Integer> asn1Tag, byte[] value) {
                return new ASN1Integer(value, new BigInteger(value));
            }
        };
    }

    @Override
    public ASN1Parser<ASN1Null> newNullParser() {
        return new ASN1Parser<ASN1Null>() {
            @Override
            public ASN1Null parse(final ASN1Tag<ASN1Null> asn1Tag, final byte[] value) throws ASN1ParseException {
                Checks.checkState(value.length == 0, "ASN.1 NULL can not have a value");
                return new ASN1Null();
            }
        };
    }

    @Override
    public ASN1Parser<ASN1ObjectIdentifier> newObjectIdentifierParser() {
        return new ASN1Parser<ASN1ObjectIdentifier>() {
            @Override
            public ASN1ObjectIdentifier parse(final ASN1Tag<ASN1ObjectIdentifier> asn1Tag, final byte[] value) throws ASN1ParseException {
                checkArgument(value.length > 0, "An ASN.1 OBJECT IDENTIFIER should have at least a one byte value");
                ByteArrayInputStream is = new ByteArrayInputStream(value);
                StringBuilder b = new StringBuilder();
                int firstTwo = is.read();
                b.append(firstTwo / 40);
                b.append('.').append(firstTwo % 40);
                while (is.available() > 0) {
                    int x = is.read();
                    if (x < 127) {
                        b.append('.').append(x);
                    } else {
                        BigInteger v = BigInteger.valueOf(x & 0x7f);
                        do {
                            x = is.read();
                            v = v.shiftLeft(7).add(BigInteger.valueOf(x & 0x7f));
                        } while (x > 127);
                        b.append('.').append(v);
                    }
                }
                return new ASN1ObjectIdentifier(value, b.toString());
            }
        };
    }

    /////////////////////////
    // Constructed parsers //
    /////////////////////////

    @Override
    public ASN1Parser<ASN1Sequence> newSequenceParser() {
        return new ASN1Parser<ASN1Sequence>() {
            @Override
            public ASN1Sequence parse(final ASN1Tag<ASN1Sequence> asn1Tag, final byte[] value) throws ASN1ParseException {
                List<ASN1Object> list = new ArrayList<>();
                try (ASN1InputStream stream = new ASN1InputStream(BERDecoder.this, value)) {
                    for (ASN1Object asn1Object : stream) {
                        list.add(asn1Object);
                    }
                } catch (IOException e) {
                    throw new ASN1ParseException(e, "Unable to parse the ASN.1 SEQUENCE contents.");
                }
                return new ASN1Sequence(list, value);
            }
        };
    }

    @Override
    public ASN1Parser<ASN1Set> newSetParser() {
        return new ASN1Parser<ASN1Set>() {
            @Override
            public ASN1Set parse(final ASN1Tag<ASN1Set> asn1Tag, final byte[] value) throws ASN1ParseException {
                HashSet<ASN1Object> asn1Objects = new HashSet<>();
                try (ASN1InputStream stream = new ASN1InputStream(BERDecoder.this, value)) {
                    for (ASN1Object asn1Object : stream) {
                        asn1Objects.add(asn1Object);
                    }
                } catch (IOException e) {
                    throw new ASN1ParseException(e, "Unable to parse ASN.1 SET contents.");
                }

                return new ASN1Set(asn1Objects, value);
            }
        };
    }

    @Override
    public ASN1Parser<ASN1TaggedObject> newTaggedObjectParser() {
        return new ASN1Parser<ASN1TaggedObject>() {
            @Override
            public ASN1TaggedObject parse(final ASN1Tag<ASN1TaggedObject> asn1Tag, final byte[] value) throws ASN1ParseException {
                return new ASN1TaggedObject(asn1Tag, value, BERDecoder.this);
            }
        };
    }

    ////////////////////
    // String parsers //
    ////////////////////

    @Override
    public ASN1Parser<ASN1BitString> newBitStringParser() {
        return new ASN1Parser<ASN1BitString>() {
            @Override
            public ASN1BitString parse(final ASN1Tag<ASN1BitString> asn1Tag, final byte[] value) throws ASN1ParseException {
                if (asn1Tag.isConstructed()) {
                    ASN1InputStream stream = new ASN1InputStream(BERDecoder.this, value);
                    try {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        int unusedBits = 0;
                        while (stream.available() > 0) {
                            ASN1Tag subTag = stream.readTag();
                            Checks.checkState(subTag.getTag() == asn1Tag.getTag(), "Expected an ASN.1 BIT STRING as Constructed object, got: %s", subTag);
                            int i = stream.readLength();
                            byte[] subValue = stream.readValue(i);
                            baos.write(subValue, 1, subValue.length - 1);
                            if (stream.available() <= 0) {
                                // Last ASN.1 BitString
                                unusedBits = subValue[0];
                            }
                        }
                        return new ASN1BitString(asn1Tag, baos.toByteArray(), unusedBits);
                    } catch (IOException e) {
                        throw new ASN1ParseException(e, "Unable to parse Constructed ASN.1 BIT STRING");
                    }
                } else {
                    byte unusedBits = value[0];
                    byte[] bits = Arrays.copyOfRange(value, 1, value.length);
                    return new ASN1BitString(asn1Tag, bits, unusedBits);
                }

            }
        };
    }

    @Override
    public ASN1Parser<ASN1OctetString> newOctetStringParser() {
        return new ASN1Parser<ASN1OctetString>() {
            @Override
            public ASN1OctetString parse(final ASN1Tag<ASN1OctetString> asn1Tag, final byte[] value) throws ASN1ParseException {
                return new ASN1OctetString(asn1Tag, value);
            }
        };
    }
}
