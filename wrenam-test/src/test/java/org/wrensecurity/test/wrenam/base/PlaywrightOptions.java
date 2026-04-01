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

package org.wrensecurity.test.wrenam.base;

import com.microsoft.playwright.BrowserType.LaunchOptions;
import com.microsoft.playwright.junit.Options;
import com.microsoft.playwright.junit.OptionsFactory;
import java.util.ArrayList;
import java.util.List;
import org.testcontainers.containers.ContainerState;

/**
 * Common Playwright test options factory.
 */
public final class PlaywrightOptions implements OptionsFactory {

    @Override
    public Options getOptions() {
        String resolverArg = new ResolverRuleBuilder()
                .addRule("wrenam.wrensecurity.test:8080", WrenAMTestBase.ingress)
                .addRule("wrenam.wrensecurity.remote:8080", WrenAMTestBase.remote)
                .build();

        boolean headlessMode = Boolean.parseBoolean(System.getProperty("playwright.headless", "true"));

        return new Options()
                .setLaunchOptions(new LaunchOptions()
                        .setArgs(List.of(resolverArg))
                        .setHeadless(headlessMode));
    }

    /**
     * Simple Chromium <code>host-resolver-rule</code> launch argument builder.
     */
    private static class ResolverRuleBuilder {

        private List<String> resolverRules = new ArrayList<>();

        /**
         * Add new rule for the source host and target container.
         */
        public ResolverRuleBuilder addRule(String source, ContainerState container) {
            if (!container.isRunning()) {
                return this;
            }
            String[] sourceParts = source.split(":", 2);
            if (sourceParts.length < 2) {
                throw new IllegalArgumentException("Missing source port: " + source);
            }
            int sourcePort = Integer.valueOf(sourceParts[1]);
            int targetPort = container.getMappedPort(sourcePort);
            resolverRules.add("MAP " + source + " " + container.getHost() + ":" + targetPort);
            return this;
        }

        /**
         * Build the final Chromium argument.
         */
        public String build() {
            return "--host-resolver-rules=" + String.join(",", resolverRules);
        }

    }

}
