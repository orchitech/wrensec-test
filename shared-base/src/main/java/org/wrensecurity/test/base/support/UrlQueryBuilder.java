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

package org.wrensecurity.test.base.support;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * URL query string builder.
 */
public final class UrlQueryBuilder {

    private Map<String, List<String>> params = new LinkedHashMap<>();

    /**
     * Add new query parameter with the given values.
     */
    public UrlQueryBuilder param(String name, Object... values) {
        params.computeIfAbsent(name, key -> new ArrayList<String>())
                .addAll(Stream.of(values).map(String::valueOf).toList());
        return this;
    }

    /**
     * Build query string containing collected parameters.
     */
    public String build() {
        return params.entrySet().stream().flatMap(param -> {
            String name = URLEncoder.encode(param.getKey(), StandardCharsets.UTF_8);
            return param.getValue().stream().map(value -> name + "="
                    + URLEncoder.encode(value, StandardCharsets.UTF_8));
        }).collect(Collectors.joining("&"));
    }

}
