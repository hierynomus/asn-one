package com.hierynomus.asn1;

import java.io.FilterOutputStream;
import java.io.OutputStream;

public abstract class ASN1OutputStream extends FilterOutputStream {
    /**
     * Creates an output stream filter built on top of the specified
     * underlying output stream.
     *
     * @param out the underlying output stream to be assigned to
     *            the field <tt>this.out</tt> for later use, or
     *            <code>null</code> if this instance is to be
     *            created without an underlying stream.
     */
    public ASN1OutputStream(OutputStream out) {
        super(out);
    }
}
