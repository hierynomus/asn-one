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
package com.hierynomus.asn1.types.string;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.types.*;

import static com.hierynomus.asn1.util.Checks.checkFormat;

/**
 * An ASN.1 STRING type can either be expressed as a Primitive encoded or Constructed encoded sequence.
 */
public abstract class ASN1String<T> extends ASN1Object<T> implements ASN1Primitive, ASN1Constructed {
    protected byte[] valueBytes;

    public ASN1String(ASN1Tag<?> tag, byte[] bytes) {
        super(tag);
        this.valueBytes = bytes;
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        if (tag.getAsn1Encoding() == ASN1Encoding.CONSTRUCTED) {
            return ASN1Tag.SEQUENCE.newParser(new BERDecoder()).parse(ASN1Tag.SEQUENCE, valueBytes).iterator();
        } else {
            return Collections.<ASN1Object>singletonList(this).iterator();
        }
    }

    public byte[] getValueBytes() {
        return Arrays.copyOf(valueBytes, valueBytes.length);
    }

    public abstract int length();

    /**
     * Maximum nesting depth accepted for constructed string segments, protecting against stack exhaustion on
     * malicious input.
     */
    private static final int MAX_SEGMENT_DEPTH = 32;

    /**
     * Concatenates the contents of a constructed string encoding into the contents of the equivalent primitive
     * encoding.
     * <p>
     * Per X.690 8.7.3 and 8.23.6 the segments of a constructed OCTET STRING or restricted character string are
     * themselves OCTET STRING encodings (UNIVERSAL 4), which may again be constructed. To be lenient towards encoders
     * in the wild, segments tagged with the string's own universal tag are accepted as well.
     *
     * @param decoder the decoder to read the segments with
     * @param universalTag the universal tag number of the string type being decoded
     * @param value the contents octets of the constructed encoding
     * @return the concatenated contents of all segments
     */
    protected static byte[] joinSegments(ASN1Decoder decoder, int universalTag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        appendSegments(decoder, universalTag, value, out, 1);
        return out.toByteArray();
    }

    private static void appendSegments(ASN1Decoder decoder, int universalTag, byte[] value, ByteArrayOutputStream out, int depth) {
        checkFormat(depth <= MAX_SEGMENT_DEPTH, "Constructed string segments nested deeper than %s levels", MAX_SEGMENT_DEPTH);
        try (ASN1InputStream stream = new ASN1InputStream(decoder, value)) {
            while (stream.available() > 0) {
                ASN1Tag<?> segmentTag = stream.readTag();
                checkFormat(segmentTag.getAsn1TagClass() == ASN1TagClass.UNIVERSAL
                        && (segmentTag.getTag() == ASN1Tag.OCTET_STRING.getTag() || segmentTag.getTag() == universalTag),
                    "Expected an OCTET STRING segment in constructed string encoding, got: %s", segmentTag);
                byte[] segment = stream.readValue(stream.readLength());
                if (segmentTag.isConstructed()) {
                    appendSegments(decoder, universalTag, segment, out, depth + 1);
                } else {
                    out.write(segment);
                }
            }
        } catch (ASN1ParseException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new ASN1ParseException(e, "Unable to parse constructed string segments");
        }
    }
}
