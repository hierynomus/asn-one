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

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Encoding;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1UnknownObject;
import com.hierynomus.asn1.types.ASN1TagClass;

import java.io.IOException;
import java.io.InputStream;

/**
 * Decoder for the Basic Encoding Rules (X.690).
 * <p>
 * By default the decoder is strict: an object with a UNIVERSAL tag that this library has no specific type for causes
 * an {@link ASN1ParseException}, so a successful parse guarantees every object was understood. A {@link #lenient()}
 * decoder instead keeps such objects as an {@link ASN1UnknownObject}, which allows reading any well-formed structure,
 * e.g. certificates containing BMPStrings. The setting also applies to objects decoded later on, such as the contents
 * of an {@link com.hierynomus.asn1.types.constructed.ASN1TaggedObject}.
 */
public class BERDecoder implements ASN1Decoder {
    private final boolean lenient;

    public BERDecoder() {
        this(false);
    }

    protected BERDecoder(boolean lenient) {
        this.lenient = lenient;
    }

    /**
     * @return a decoder that keeps objects with an unknown UNIVERSAL tag as {@link ASN1UnknownObject} instead of failing
     */
    public static BERDecoder lenient() {
        return new BERDecoder(true);
    }

    /**
     * @return whether objects with an unknown UNIVERSAL tag are kept as {@link ASN1UnknownObject} instead of failing
     */
    public boolean isLenient() {
        return lenient;
    }

    private ASN1Tag<?> lookupTag(ASN1TagClass asn1TagClass, int tag) {
        return lenient ? ASN1Tag.forTagOrUnknown(asn1TagClass, tag) : ASN1Tag.forTag(asn1TagClass, tag);
    }

    @Override
    public ASN1Tag<? extends ASN1Object> readTag(InputStream is) {
        try {
            int tagByte = is.read();
            if (tagByte < 0) {
                throw new ASN1ParseException("Unexpected end of stream, expected an ASN.1 tag");
            }
            ASN1TagClass asn1TagClass = ASN1TagClass.parseClass((byte) tagByte);
            ASN1Encoding asn1Encoding = ASN1Encoding.parseEncoding((byte) tagByte);
            int tag = tagByte & 0x1f;

            if (tag <= 0x1e) {
                return lookupTag(asn1TagClass, tag).asEncoded(asn1Encoding);
            } else {
                int iTag = 0;
                int read = is.read();
                if ((read & 0x7f) == 0) {
                    throw new ASN1ParseException("corrupted stream - invalid high tag number found");
                }

                while ((read >= 0) && ((read & 0x80) != 0)) {
                    iTag |= (read & 0x7f);
                    iTag <<= 7;
                    read = is.read();
                }

                if (read < 0) {
                    throw new ASN1ParseException("EOF found inside tag value.");
                }

                iTag |= (read & 0x7f);

                return lookupTag(asn1TagClass, iTag).asEncoded(asn1Encoding);
            }
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to parse ASN.1 tag", ioe);
        }
    }

    @Override
    public int readLength(InputStream is) {
        try {
            int firstByte = is.read();
            if (firstByte < 0) {
                throw new ASN1ParseException("Unexpected end of stream, expected the length of the ASN.1 object");
            }
            if (firstByte <= 0x7f) {
                // Short form (X.690 8.1.3.4)
                return firstByte;
            }
            int nrBytes = firstByte & 0x7f;
            if (nrBytes == 0) {
                // 0x80 denotes the indefinite form (X.690 8.1.3.6)
                throw new ASN1ParseException("The indefinite length form is not (yet) supported!");
            }
            if (nrBytes > 4) {
                throw new ASN1ParseException("ASN.1 length of %s bytes is not supported", nrBytes);
            }
            long longLength = 0;
            for (int i = 0; i < nrBytes; i++) {
                int b = is.read();
                if (b < 0) {
                    throw new ASN1ParseException("Unexpected end of stream while reading the length of the ASN.1 object");
                }
                longLength = (longLength << 8) | b;
            }
            if (longLength > Integer.MAX_VALUE) {
                throw new ASN1ParseException("ASN.1 length %s is not supported", longLength);
            }
            return (int) longLength;
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
            if (count < length) {
                throw new ASN1ParseException("Unexpected end of stream, ASN.1 object has length %s but only %s bytes are available", length, count);
            }
            return value;
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to read the value of the ASN.1 object", ioe);
        }
    }
}
