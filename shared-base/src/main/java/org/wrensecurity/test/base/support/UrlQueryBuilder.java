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
public class UrlQueryBuilder {

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
