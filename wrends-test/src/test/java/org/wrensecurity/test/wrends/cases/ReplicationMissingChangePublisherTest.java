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

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.wrensecurity.test.base.support.CustomAssertions.assertSuccess;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.BASE_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_DN;
import static org.wrensecurity.test.base.wrends.WrenDSDefaults.ROOT_USER_PASSWORD;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.forgerock.opendj.ldap.ByteString;
import org.forgerock.opendj.ldap.SearchScope;
import org.forgerock.opendj.ldap.responses.Result;
import org.forgerock.opendj.ldap.responses.SearchResultEntry;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.Network;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.wrensecurity.test.base.wrends.WrenDSContainer;

/**
 * Verifies that missing-change recovery continues to publish new changes when
 * {@code ds-sync-hist} contains many migrated history values from other replication
 * servers.
 *
 * @see <a href="https://github.com/WrenSecurity/wrends/pull/142">Wren:DS PR #142</a>
 */
@Testcontainers
class ReplicationMissingChangePublisherTest {

    private static final String SOURCE_ALIAS = "wrends-test1";

    private static final String DESTINATION_ALIAS = "wrends-test2";

    private static final String ENTRY_DN = sampleEntryDn(0);

    private static final String HISTORY_LDIF_PATH = "/tmp/fake-history.ldif";

    private static final String REPLICATION_REPAIR_CONTROL_OID = "1.3.6.1.4.1.26027.1.5.2";

    private static final Pattern CSN_PATTERN = Pattern.compile("(?i)([0-9a-f]{28})");

    private static final int CURSOR_ENTRY_LIMIT = 100_000;

    /**
     * Number of sample entries used for seeded history ({@code wrends.recovery.history.entries}).
     */
    private static final int HISTORY_ENTRY_COUNT = Integer.getInteger("wrends.recovery.history.entries", 1_500);

    /**
     * Number of generated history values per index range side ({@code wrends.recovery.history.valuesPerSide}).
     */
    private static final int HISTORY_VALUES_PER_SIDE = Integer.getInteger("wrends.recovery.history.valuesPerSide", 160);

    /**
     * Delay between background writes ({@code wrends.recovery.writeIntervalMillis}).
     */
    private static final long WRITE_INTERVAL_MILLIS = Long.getLong("wrends.recovery.writeIntervalMillis", 20L);

    /**
     * Timeout for ordinary replication waits ({@code wrends.recovery.replicationTimeoutSeconds}).
     */
    private static final Duration REPLICATION_TIMEOUT = Duration.ofSeconds(Long.getLong("wrends.recovery.replicationTimeoutSeconds", 60L));

    /**
     * Timeout for the final post-recovery replication assertion ({@code wrends.recovery.timeoutSeconds}).
     */
    private static final Duration RECOVERY_TIMEOUT = Duration.ofSeconds(Long.getLong("wrends.recovery.timeoutSeconds", 45L));

    /**
     * How far the synthetic local CSN is moved ahead ({@code wrends.recovery.aheadMinutes}).
     */
    private static final Duration FORCED_RECOVERY_AHEAD = Duration.ofMinutes(Long.getLong("wrends.recovery.aheadMinutes", 60L));

    @AutoClose
    private final Network network = Network.newNetwork();

    @Container
    private final WrenDSContainer source = new WrenDSContainer()
            .withSampleData(HISTORY_ENTRY_COUNT)
            .withNetwork(network)
            .withNetworkAliases(SOURCE_ALIAS);

    @Container
    private final WrenDSContainer destination = new WrenDSContainer()
            .withNetwork(network)
            .withNetworkAliases(DESTINATION_ALIAS);

    /**
     * Initialize replication, seed problematic history, rebuild the index under
     * write load, then assert that a new change is still replicated.
     */
    @Test
    void testMissingChangePublisherRecoversWithMigratedHistory() throws Exception {
        assumeHistorySeedExceedsRangeCursorLimit();

        enableReplication();
        initializeReplication();

        String sourceCsn = createSourceHistoryAndGetLatestCsn();
        int sourceServerId = getServerId(sourceCsn);
        seedHistory(sourceServerId, getCsnTime(sourceCsn));

        AtomicBoolean writing = new AtomicBoolean(true);
        AtomicInteger successfulWrites = new AtomicInteger();
        Thread writer = startWriteLoad(writing, successfulWrites);
        try {
            await("Wait for write load before rebuild-index")
                    .atMost(REPLICATION_TIMEOUT)
                    .untilAsserted(() -> assertTrue(successfulWrites.get() >= 5,
                            "Write load did not produce local changes"));

            int writesBeforeRebuild = successfulWrites.get();
            // Online rebuild disables and re-enables the backend. Re-enable reloads
            // ServerState from ds-sync-hist, picks up the seeded future local CSN,
            // and triggers missing-change recovery.
            rebuildUidIndex(source);
            await("Wait for write load after rebuild-index")
                    .atMost(REPLICATION_TIMEOUT)
                    .untilAsserted(() -> assertTrue(successfulWrites.get() > writesBeforeRebuild,
                            "Write load did not straddle rebuild-index"));

            assertNewChangesAreReplicatedAfterRecovery();
        } finally {
            writing.set(false);
            writer.interrupt();
            writer.join(Duration.ofSeconds(5).toMillis());
            assertFalse(writer.isAlive(), "Write-load thread did not stop");
        }
    }

    private void enableReplication() throws Exception {
        ExecResult enableResult = source.execInContainer(
                "dsreplication", "enable",
                "--adminUID", "admin",
                "--adminPassword", ROOT_USER_PASSWORD,
                "--trustAll",
                "--no-prompt",
                "--baseDN", BASE_DN,
                "--host1", SOURCE_ALIAS,
                "--port1", "4444",
                "--bindDN1", ROOT_USER_DN,
                "--bindPassword1", ROOT_USER_PASSWORD,
                "--noReplicationServer1",
                "--host2", DESTINATION_ALIAS,
                "--port2", "4444",
                "--bindDN2", ROOT_USER_DN,
                "--bindPassword2", ROOT_USER_PASSWORD,
                "--replicationPort2", "8989");
        assertSuccess(enableResult, "Failed to enable replication");
    }

    private void initializeReplication() throws Exception {
        ExecResult initResult = source.execInContainer(
                "dsreplication", "initialize-all",
                "--adminUID", "admin",
                "--adminPassword", ROOT_USER_PASSWORD,
                "--trustAll",
                "--no-prompt",
                "--baseDN", BASE_DN,
                "--hostname", SOURCE_ALIAS,
                "--port", "4444");
        assertSuccess(initResult, "Failed to initialize replication");
        waitForEntry(destination, sampleEntryDn(HISTORY_ENTRY_COUNT - 1), REPLICATION_TIMEOUT);
    }

    private String createSourceHistoryAndGetLatestCsn() throws Exception {
        String marker = "server-id-discovery-" + System.nanoTime();
        replaceAttribute(source, ENTRY_DN, "description", marker);
        waitForAttribute(destination, ENTRY_DN, "description", marker, REPLICATION_TIMEOUT);

        List<String> csns = getHistoricalCsns(source, ENTRY_DN);
        assertFalse(csns.isEmpty(), "Source change did not create ds-sync-hist data");
        return csns.stream()
                .max(Comparator.comparingLong(ReplicationMissingChangePublisherTest::getCsnTime))
                .orElseThrow();
    }

    private void seedHistory(int sourceServerId, long sourceCsnTime) throws Exception {
        String ldif = buildHistoryLdif(sourceServerId, sourceCsnTime);
        source.copyFileToContainer(Transferable.of(ldif.getBytes(StandardCharsets.UTF_8)), HISTORY_LDIF_PATH);

        ExecResult seedResult = source.execInContainer(
                "ldapmodify",
                "-h", "localhost",
                "-p", "1389",
                "-D", ROOT_USER_DN,
                "-w", ROOT_USER_PASSWORD,
                "-J", REPLICATION_REPAIR_CONTROL_OID,
                "-f", HISTORY_LDIF_PATH);
        assertSuccess(seedResult, "Failed to seed migrated ds-sync-hist values");
    }

    private static String buildHistoryLdif(int sourceServerId, long sourceCsnTime) {
        int foreignHigherServerId = getHigherServerId(sourceServerId);
        // Inflates the old <= index range for the source server ID.
        long localPastTime = sourceCsnTime - Duration.ofHours(2).toMillis();
        // Inflates the old >= index range with another server ID.
        long foreignFutureTime = sourceCsnTime + Duration.ofHours(2).toMillis();
        // Forces missing-change recovery after rebuild-index.
        long stateAheadTime = sourceCsnTime + FORCED_RECOVERY_AHEAD.toMillis();
        int estimatedHistoryLineLength = 90;
        StringBuilder ldif = new StringBuilder(
                HISTORY_ENTRY_COUNT * HISTORY_VALUES_PER_SIDE * 2 * estimatedHistoryLineLength);

        for (int entry = 0; entry < HISTORY_ENTRY_COUNT; entry++) {
            StringBuilder historyValues = new StringBuilder(
                    HISTORY_VALUES_PER_SIDE * 2 * estimatedHistoryLineLength);
            for (int value = 0; value < HISTORY_VALUES_PER_SIDE; value++) {
                int sequence = entry * HISTORY_VALUES_PER_SIDE + value + 1;
                historyValues.append("""
                        ds-sync-hist: description:%s:repl:%s
                        """.formatted(formatCsn(localPastTime + sequence, sourceServerId,
                        sequence), "local-past-" + sequence));
                historyValues.append("""
                        ds-sync-hist: description:%s:repl:%s
                        """.formatted(formatCsn(foreignFutureTime + sequence,
                        foreignHigherServerId, sequence), "foreign-future-" + sequence));
            }
            // One future local CSN is enough to trigger missing-change recovery.
            if (entry == 0) {
                int sequence = HISTORY_ENTRY_COUNT * HISTORY_VALUES_PER_SIDE + 1;
                historyValues.append("""
                        ds-sync-hist: description:%s:repl:%s
                        """.formatted(formatCsn(stateAheadTime, sourceServerId, sequence),
                        "state-ahead"));
            }
            ldif.append("""
                    dn: %s
                    changetype: modify
                    add: ds-sync-hist
                    %s-

                    """.formatted(sampleEntryDn(entry), historyValues));
        }
        return ldif.toString();
    }

    private static Thread startWriteLoad(WrenDSContainer container, AtomicBoolean writing,
            AtomicInteger successfulWrites) {
        Thread writer = new Thread(() -> {
            int value = 0;
            while (writing.get()) {
                String description = "recovery-load-" + value++;
                if (tryReplaceAttribute(container, ENTRY_DN, "description", description)) {
                    successfulWrites.incrementAndGet();
                }
                try {
                    Thread.sleep(WRITE_INTERVAL_MILLIS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }, "wrends-recovery-write-load");
        writer.setDaemon(true);
        writer.start();
        return writer;
    }

    private Thread startWriteLoad(AtomicBoolean writing, AtomicInteger successfulWrites) {
        return startWriteLoad(source, writing, successfulWrites);
    }

    private static void rebuildUidIndex(WrenDSContainer container) throws Exception {
        ExecResult rebuildResult = container.execInContainer(
                "rebuild-index",
                "--baseDN", BASE_DN,
                "--index", "uid",
                "--port", "4444",
                "--bindDN", ROOT_USER_DN,
                "--bindPassword", ROOT_USER_PASSWORD,
                "--trustAll");
        assertSuccess(rebuildResult, "Failed to rebuild uid index");
    }

    private void assertNewChangesAreReplicatedAfterRecovery() throws Exception {
        int valueBase = Math.floorMod(System.identityHashCode(this), 9_000);
        String value = String.format(Locale.ROOT, "%04d", valueBase);

        replaceAttribute(source, ENTRY_DN, "roomNumber", value);
        await("Wait for replication after missing-change recovery")
                .atMost(RECOVERY_TIMEOUT)
                .pollInterval(Duration.ofSeconds(1))
                .untilAsserted(() -> assertAttributeValue(destination, ENTRY_DN, "roomNumber", value));
    }

    private static void replaceAttribute(WrenDSContainer container, String dn,
            String attributeName, String value) throws Exception {
        try (var connection = container.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().modify(
                    "dn: " + dn,
                    "changetype: modify",
                    "replace: " + attributeName,
                    attributeName + ": " + value);
            assertTrue(result.isSuccess(), "Modify request failed: " + result);
        }
    }

    private static boolean tryReplaceAttribute(WrenDSContainer container, String dn,
            String attributeName, String value) {
        try (var connection = container.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            Result result = connection.unwrap().modify(
                    "dn: " + dn,
                    "changetype: modify",
                    "replace: " + attributeName,
                    attributeName + ": " + value);
            return result.isSuccess();
        } catch (Exception e) {
            return false;
        }
    }

    private static void waitForEntry(WrenDSContainer container, String dn, Duration timeout) {
        await("Wait for replicated entry " + dn).atMost(timeout).untilAsserted(() -> {
            try (var connection = container.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
                SearchResultEntry entry = connection.unwrap().searchSingleEntry(
                        dn, SearchScope.BASE_OBJECT, "(objectClass=*)", "dn");
                assertNotNull(entry, "Entry was not replicated");
            }
        });
    }

    private static void waitForAttribute(WrenDSContainer container, String dn,
            String attributeName, String expectedValue, Duration timeout) {
        await("Wait for replicated " + attributeName + " " + expectedValue)
                .atMost(timeout)
                .untilAsserted(() -> {
                    try (var connection = container.getLdapConnection(
                            ROOT_USER_DN, ROOT_USER_PASSWORD)) {
                        SearchResultEntry entry = connection.unwrap().searchSingleEntry(
                                dn, SearchScope.BASE_OBJECT, "(objectClass=*)", attributeName);
                        assertNotNull(entry, "Entry was not replicated");
                        var attribute = entry.getAttribute(attributeName);
                        assertNotNull(attribute, () -> attributeName + " was not replicated");
                        assertTrue(attribute.stream()
                                .map(ByteString::toString)
                                .anyMatch(expectedValue::equals),
                                () -> attributeName + " was not replicated to "
                                        + expectedValue);
                    }
                });
    }

    private static void assertAttributeValue(WrenDSContainer container, String dn,
            String attributeName, String expectedValue) throws Exception {
        try (var connection = container.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            SearchResultEntry entry = connection.unwrap().searchSingleEntry(
                    dn, SearchScope.BASE_OBJECT, "(objectClass=*)", attributeName);
            assertNotNull(entry, "Entry was not replicated");
            var attribute = entry.getAttribute(attributeName);
            assertNotNull(attribute, () -> attributeName + " was not replicated");
            assertTrue(attribute.stream()
                    .map(ByteString::toString)
                    .anyMatch(expectedValue::equals),
                    () -> attributeName + " was not replicated to " + expectedValue);
        }
    }

    /**
     * Extracts CSN tokens from {@code ds-sync-hist} values of the given entry.
     */
    private static List<String> getHistoricalCsns(WrenDSContainer container, String dn) throws Exception {
        try (var connection = container.getLdapConnection(ROOT_USER_DN, ROOT_USER_PASSWORD)) {
            SearchResultEntry entry = connection.unwrap()
                    .searchSingleEntry(dn, SearchScope.BASE_OBJECT, "(objectClass=*)", "ds-sync-hist");
            assertNotNull(entry, "Entry is missing: " + dn);
            var history = entry.getAttribute("ds-sync-hist");
            if (history == null) {
                return List.of();
            }

            List<String> csns = new ArrayList<>();
            history.stream()
                    .map(ByteString::toString)
                    .forEach(value -> {
                        Matcher matcher = CSN_PATTERN.matcher(value);
                        while (matcher.find()) {
                            csns.add(matcher.group(1).toLowerCase(Locale.ROOT));
                        }
                    });
            return csns;
        }
    }

    private static void assumeHistorySeedExceedsRangeCursorLimit() {
        long valuesPerRangeSide = (long) HISTORY_ENTRY_COUNT * HISTORY_VALUES_PER_SIDE;
        assumeTrue(valuesPerRangeSide > CURSOR_ENTRY_LIMIT,
                "Migrated ds-sync-hist seed must exceed " + CURSOR_ENTRY_LIMIT
                        + " values per range side, got " + valuesPerRangeSide);
    }

    private static String sampleEntryDn(int number) {
        return "uid=user." + number + ",ou=People," + BASE_DN;
    }

    private static String formatCsn(long timeMillis, int serverId, int sequence) {
        return String.format(Locale.ROOT, "%016x%04x%08x", timeMillis, serverId, sequence);
    }

    private static int getHigherServerId(int sourceServerId) {
        assertTrue(sourceServerId < 0xffff, "Test requires room for a higher foreign server ID");
        return sourceServerId + 1;
    }

    private static long getCsnTime(String csn) {
        return Long.parseUnsignedLong(csn.substring(0, 16), 16);
    }

    private static int getServerId(String csn) {
        return Integer.parseInt(csn.substring(16, 20), 16);
    }

}
