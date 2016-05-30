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

import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1Tag.ASN1TagClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class ASN1InputStream extends FilterInputStream implements Iterable<ASN1Object> {
    private static final Logger logger = LoggerFactory.getLogger(ASN1InputStream.class);

    public ASN1InputStream(InputStream wrapped) {
        super(wrapped);
    }

    public ASN1InputStream(byte[] value) {
        super(new ByteArrayInputStream(value));
    }

    public <T extends ASN1Object> T readObject() throws ASN1ParseException {
        try {
            ASN1Tag tag = readTag();
            logger.trace("Read ASN.1 tag {}", tag);
            int length = readLength();
            logger.trace("Read ASN.1 object length: {}", length);
            byte[] value = new byte[length];
            int count = 0;
            int read = 0;
            while (count < length && ((read = read(value, count, length - count)) != -1)) {
                count += read;
            }

            //noinspection unchecked
            return (T) tag.newParser().parse(value);
        } catch (ASN1ParseException pe) {
            throw pe;
        } catch (Exception e) {
            throw new ASN1ParseException(e, "Cannot parse ASN.1 object from stream");
        }
    }

    public Iterator<ASN1Object> iterator() {
        return new Iterator<ASN1Object>() {
            @Override
            public boolean hasNext() {
                try {
                    return available() > 0;
                } catch (IOException e) {
                    // Or throw an exception?
                    return false;
                }
            }

            @Override
            public ASN1Object next() {
                return readObject();
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException("Remove not supported on ASN.1 InputStream iterator");
            }
        };
    }

    private ASN1Tag readTag() throws IOException {
        int tagByte = read();
        ASN1TagClass asn1TagClass = ASN1TagClass.parseClass((byte) tagByte);
        ASN1Tag.ASN1Encoding asn1Encoding = ASN1Tag.ASN1Encoding.parseEncoding((byte) tagByte);
        int tag = tagByte & 0x1f;
        if (tag <= 0x1e) {
            return ASN1Tag.forTag(asn1TagClass, tag).asEncoded(asn1Encoding);
        } else {
            int iTag = 0;
            int read = read();
            do {
                iTag <<= 7;
                iTag |= (read & 0x7f);
                read = read();
            } while ((read & 0x80) > 0);
            return ASN1Tag.forTag(asn1TagClass, iTag).asEncoded(asn1Encoding);
        }
    }

    private int readLength() throws IOException {
        int firstByte = read();
        if (firstByte < 0x7f) {
            return firstByte;
        }
        int nrBytes = firstByte & 0x7f;
        int longLength = 0;
        for (int i = 0; i < nrBytes; i++) {
            longLength = longLength << 8;
            longLength += read();
        }

        if (longLength == 0) {
            throw new ASN1ParseException("The indefinite length form is not (yet) supported!");
        }

        return longLength;
    }
}
