/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 Wren Security
 */

package org.wrensecurity.test.wrends.base;

import com.github.dockerjava.api.async.ResultCallbackTemplate;
import com.github.dockerjava.api.model.Frame;

/**
 * Simple string aggregating Docker result callback.
 */
public class StringBufferResultCallback extends ResultCallbackTemplate<StringBufferResultCallback, Frame> {

    private final StringBuffer output;

    /**
     * Create new callback instance with empty string buffer.
     */
    public StringBufferResultCallback() {
        this(new StringBuffer());
    }

    /**
     * Create new callback instance with the given string buffer.
     */
    public StringBufferResultCallback(StringBuffer output) {
        this.output = output;
    }

    @Override
    public void onNext(Frame object) {
        output.append(new String(object.getPayload()));
    }

    @Override
    public String toString() {
        return output.toString();
    }

}
