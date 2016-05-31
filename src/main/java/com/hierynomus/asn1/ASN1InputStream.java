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

import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class ASN1InputStream extends FilterInputStream implements Iterable<ASN1Object> {
    private static final Logger logger = LoggerFactory.getLogger(ASN1InputStream.class);
    private final ASN1Decoder decoder;

    public ASN1InputStream(ASN1Decoder decoder, InputStream wrapped) {
        super(wrapped);
        this.decoder = decoder;
    }

    public ASN1InputStream(ASN1Decoder decoder, byte[] value) {
        super(new ByteArrayInputStream(value));
        this.decoder = decoder;
    }

    public <T extends ASN1Object> T readObject() throws ASN1ParseException {
        try {
            ASN1Tag tag = decoder.readTag(this);
            logger.trace("Read ASN.1 tag {}", tag);
            int length = decoder.readLength(this);
            logger.trace("Read ASN.1 object length: {}", length);
            byte[] value = decoder.readValue(length, this);

            //noinspection unchecked
            return (T) tag.newParser(decoder).parse(tag, value);
        } catch (ASN1ParseException pe) {
            throw pe;
        } catch (Exception e) {
            throw new ASN1ParseException(e, "Cannot parse ASN.1 object from stream");
        }
    }

    public byte[] readValue(int length) throws IOException {
        return decoder.readValue(length, this);
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

    public ASN1Tag readTag() throws IOException {
        return decoder.readTag(this);
    }

    public int readLength() throws IOException {
        return decoder.readLength(this);
    }
}
