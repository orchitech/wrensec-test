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
package org.wrensecurity.test.wrends.cases;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.BASE_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_PASSWORD;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.assertSuccess;
import static org.wrensecurity.test.wrends.base.WrenDSCommands.ldapModify;

import org.forgerock.opendj.ldap.ByteString;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

@Testcontainers
public class SchemaOperationsTest {

    @Container
    @SuppressWarnings("resource")
    private static WrenDSContainer wrends = new WrenDSContainer().withSampleData()
            .withCopyToContainer(MountableFile.forClasspathResource("schema"), "/tmp/schema");

    @Test
    public void testAddCustomAttributeAndObjectClass() throws Exception {
        // Add custom attribute type
        ExecResult attrResult = ldapModify(wrends, "/tmp/schema/blogUrlAt.ldif");
        assertSuccess(attrResult, "Failed to add custom attribute type");

        // Add custom object class
        ExecResult ocResult = ldapModify(wrends, "/tmp/schema/blogUrlOc.ldif");
        assertSuccess(ocResult, "Failed to add custom object class");

        // Create entry using custom object class
        ExecResult entryResult = ldapModify(wrends, "/tmp/schema/blogger.ldif");
        assertSuccess(entryResult, "Failed to create entry with custom object class");

        // Search schema for the custom object class
        try (var connection = wrends.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            SearchResultEntry schemaEntry = connection.unwrap().searchSingleEntry(
                    "cn=schema", SearchScope.BASE_OBJECT, "(objectclass=*)", "objectClasses");

            assertTrue(schemaEntry.getAttribute("objectClasses").stream()
                    .map(ByteString::toString)
                    .anyMatch(value -> value.contains("blogger")),
                    "Missing imported object class");

            SearchResultEntry blogEntry = connection.unwrap().searchSingleEntry(
                    BASE_DN, SearchScope.WHOLE_SUBTREE, "(blog=Test)", "blog");
            assertNotNull(blogEntry.getAttribute("blog"));
        }
    }

}
