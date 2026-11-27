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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

import static com.hierynomus.asn1.util.Checks.checkFormat;

public class ASN1InputStream extends FilterInputStream implements Iterable<ASN1Object> {
    private static final Logger logger = LoggerFactory.getLogger(ASN1InputStream.class);
    private final ASN1Decoder decoder;

    /**
     * Maximum nesting depth of constructed objects (SEQUENCE, SET, tagged objects, ...) that is parsed. Parsing is
     * recursive, so without a limit a few kilobytes of deeply nested input could exhaust the stack. Real-world
     * structures such as X.509 certificates or CMS messages stay well below this.
     */
    public static final int MAX_NESTING_DEPTH = 64;

    // Parsing of nested objects recurses through new ASN1InputStream instances, so the depth is tracked per thread.
    private static final ThreadLocal<int[]> NESTING_DEPTH = new ThreadLocal<int[]>() {
        @Override
        protected int[] initialValue() {
            return new int[1];
        }
    };

    public ASN1InputStream(ASN1Decoder decoder, InputStream wrapped) {
        super(wrapped);
        this.decoder = decoder;
    }

    public ASN1InputStream(ASN1Decoder decoder, byte[] value) {
        super(new ByteArrayInputStream(value));
        this.decoder = decoder;
    }

    public <T extends ASN1Object> T readObject() {
        int[] depth = NESTING_DEPTH.get();
        checkFormat(depth[0] < MAX_NESTING_DEPTH, "ASN.1 structure is nested deeper than %s levels", MAX_NESTING_DEPTH);
        depth[0]++;
        try {
            ASN1Tag tag = decoder.readTag(this);
            logger.trace("Read ASN.1 tag {}", tag);
            int length = decoder.readLength(this);
            logger.trace("Read ASN.1 object length: {}", length);
            byte[] value = decoder.readValue(length, this);

            //noinspection unchecked
            ASN1Object parse = tag.newParser(decoder).parse(tag, value);
            logger.debug("Read ASN.1 object: {}", parse);
            return (T) parse;
        } catch (ASN1ParseException pe) {
            throw pe;
        } catch (Exception e) {
            throw new ASN1ParseException(e, "Cannot parse ASN.1 object from stream");
        } finally {
            if (--depth[0] == 0) {
                NESTING_DEPTH.remove();
            }
        }
    }

    public byte[] readValue(int length) {
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
                if (!hasNext()) {
                    throw new NoSuchElementException("No more ASN.1 objects in stream");
                }
                // Let an ASN1ParseException propagate as is, so the actual cause is not lost.
                return readObject();
            }

            @Override
            public void remove() {
                throw new UnsupportedOperationException("Remove not supported on ASN.1 InputStream iterator");
            }
        };
    }

    public ASN1Tag readTag() {
        return decoder.readTag(this);
    }

    public int readLength() {
        return decoder.readLength(this);
    }
}
