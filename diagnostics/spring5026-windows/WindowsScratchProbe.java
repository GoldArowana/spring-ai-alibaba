/*
 * Copyright 2025-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import com.sun.nio.file.ExtendedOpenOption;
import com.sun.security.auth.module.NTSystem;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Synthetic Windows scratch-file experiment, not production saver code. */
public final class WindowsScratchProbe {
    private static final byte[] PAYLOAD = "SYNTHETIC-CHECKPOINT-5026".getBytes(StandardCharsets.UTF_8);
    private static final Set<AclEntryPermission> FULL = EnumSet.allOf(AclEntryPermission.class);
    private static final Set<AclEntryPermission> READ = EnumSet.of(AclEntryPermission.READ_DATA,
            AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS,
            AclEntryPermission.READ_ACL, AclEntryPermission.EXECUTE, AclEntryPermission.SYNCHRONIZE);

    public static void main(String[] args) throws Exception {
        Path output = Path.of(args[0]).toAbsolutePath();
        Path scripts = Path.of(args[1]).toAbsolutePath();
        Files.createDirectories(output);
        Map<String, Object> report = new LinkedHashMap<>();
        List<Map<String, Object>> cases = new ArrayList<>();
        report.put("started_at", Instant.now().toString());
        report.put("mode", "synthetic_private_scratch_primitive_only");
        report.put("actual_saver_head_context", "c708d4ff482184446b79111f5de58fb635156aa3");
        report.put("java_runtime", System.getProperty("java.runtime.version"));
        report.put("java_vendor", System.getProperty("java.vendor"));
        report.put("spoofable_user_name", System.getProperty("user.name"));
        report.put("runner_image", System.getenv("ImageVersion"));
        report.put("cases", cases);
        report.put("production_saver_or_restore_tested", false);
        Path root = null;
        int exit = 2;
        try {
            if (!System.getProperty("os.name").startsWith("Windows")) throw new IOException("Windows required");
            NTSystem identity = new NTSystem();
            String account = identity.getDomain() == null || identity.getDomain().isBlank()
                    ? identity.getName() : identity.getDomain() + "\\" + identity.getName();
            String sid = Objects.requireNonNull(identity.getUserSID(), "NTSystem SID unavailable");
            report.put("ntsystem_account", account);
            report.put("ntsystem_sid", sid);
            report.put("ntsystem_under_impersonation_tested", false);
            root = Files.createTempDirectory(Path.of(System.getenv("RUNNER_TEMP")), "spring5026-scratch-");
            report.put("fixture_root", root.toString());
            report.put("filesystem_provider", root.getFileSystem().provider().getClass().getName());
            report.put("file_store", Files.getFileStore(root).type());
            if (!Files.getFileStore(root).supportsFileAttributeView(AclFileAttributeView.class)) {
                throw new IOException("ACL-capable store required; no private-scratch claim");
            }
            UserPrincipalLookupService lookup = root.getFileSystem().getUserPrincipalLookupService();
            UserPrincipal caller = lookup.lookupPrincipalByName(account);
            // Resolve the well-known anonymous SID through .NET; no account is created.
            Path anonymousName = output.resolve("anonymous-account.txt");
            Process name = new ProcessBuilder("pwsh", "-NoProfile", "-Command",
                    "([System.Security.Principal.SecurityIdentifier]'S-1-5-7').Translate([System.Security.Principal.NTAccount]).Value")
                    .redirectOutput(anonymousName.toFile()).redirectError(output.resolve("anonymous-name.stderr").toFile()).start();
            if (!name.waitFor(20, TimeUnit.SECONDS) || name.exitValue() != 0) {
                name.destroyForcibly(); throw new IOException("Anonymous account lookup failed");
            }
            UserPrincipal anonymous = lookup.lookupPrincipalByName(Files.readString(anonymousName).replace("\uFEFF", "").trim());
            AclEntry callerRule = AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(caller).setPermissions(FULL).build();
            AclEntry inheritCaller = AclEntry.newBuilder(callerRule)
                    .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT).build();
            AclEntry inheritObserver = AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(anonymous).setPermissions(READ)
                    .setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT).build();
            Files.getFileAttributeView(root, AclFileAttributeView.class).setAcl(List.of(inheritCaller, inheritObserver));
            report.put("fixture_acl", Files.getFileAttributeView(root, AclFileAttributeView.class).getAcl()
                    .stream().map(Object::toString).toList());
            Path positive = root.resolve("positive.txt");
            Files.write(positive, PAYLOAD);
            Files.getFileAttributeView(positive, AclFileAttributeView.class).setAcl(List.of(callerRule,
                    AclEntry.newBuilder(inheritObserver).setFlags(Set.of()).build()));
            report.put("positive_control_acl", Files.getFileAttributeView(positive, AclFileAttributeView.class).getAcl()
                    .stream().map(Object::toString).toList());
            Path ipc = Files.createDirectory(root.resolve("ipc"));
            for (String role : List.of("new-stage", "old-backup")) {
                for (String variant : List.of("initial-acl", "late-acl", "exclusive-init")) {
                    Map<String, Object> result = new LinkedHashMap<>();
                    cases.add(result);
                    try { probe(root, ipc, output, scripts, caller, callerRule, account, sid, role, variant, result); }
                    catch (Exception failure) { result.put("error", failure.toString()); result.put("candidate_private", false); }
                }
            }
            boolean complete = cases.size() == 6 && cases.stream().allMatch(x -> Boolean.TRUE.equals(x.get("observer_valid")));
            boolean candidate = cases.stream().filter(x -> "exclusive-init".equals(x.get("variant")))
                    .allMatch(x -> Boolean.TRUE.equals(x.get("candidate_private")));
            report.put("diagnostic_observations_complete", complete);
            report.put("exclusive_init_candidate_private", complete && candidate);
            report.put("initial_and_late_acl_are_diagnostic_controls", true);
            exit = complete && candidate ? 0 : 2;
        }
        catch (Exception failure) { report.put("setup_error", failure.toString()); }
        finally {
            if (root != null) {
                try (var paths = Files.walk(root)) {
                    for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
                }
                catch (Exception failure) { report.put("cleanup_error", failure.toString()); exit = 2; }
            }
            report.put("finished_at", Instant.now().toString());
            report.put("exit_code", exit);
            Files.writeString(output.resolve("report.json"), json(report), StandardCharsets.UTF_8);
        }
        System.exit(exit);
    }

    private static void probe(Path root, Path ipc, Path output, Path scripts, UserPrincipal caller,
            AclEntry rule, String account, String sid, String role, String variant, Map<String, Object> result) throws Exception {
        String id = role + "-" + variant;
        Path target = root.resolve(id + ".tmp");
        Path signal = ipc.resolve(id);
        Path log = output.resolve(id);
        Files.createDirectories(log);
        result.put("role", role); result.put("variant", variant);
        result.put("negative_control", !variant.equals("exclusive-init"));
        Set<OpenOption> options = new HashSet<>(Set.of(StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE));
        if (variant.equals("exclusive-init")) {
            options.add(ExtendedOpenOption.NOSHARE_READ); options.add(ExtendedOpenOption.NOSHARE_WRITE);
        }
        FileAttribute<?>[] attributes = variant.equals("initial-acl")
                ? new FileAttribute<?>[]{new FileAttribute<List<AclEntry>>() {
                    public String name() { return "acl:acl"; }
                    public List<AclEntry> value() { return List.of(rule); }
                }} : new FileAttribute<?>[0];
        Process observer = null;
        try (FileChannel file = FileChannel.open(target, options, attributes)) {
            AclFileAttributeView view = Files.getFileAttributeView(target, AclFileAttributeView.class);
            result.put("initial_acl_before_payload", view.getAcl().stream().map(Object::toString).toList());
            result.put("initial_size", file.size());
            observer = new ProcessBuilder("pwsh", "-NoProfile", "-File", scripts.resolve("observer.ps1").toString(),
                    "-Directory", root.toString(), "-Leaf", target.getFileName().toString(),
                    "-SignalPrefix", signal.toString(), "-Output", log.toString(),
                    "-CallerAccount", account, "-ExpectedSid", sid)
                    .redirectOutput(log.resolve("stdout.txt").toFile()).redirectError(log.resolve("stderr.txt").toFile()).start();
            waitFor(signal.resolveSibling(id + ".ready"), observer);
            Properties ready = properties(signal.resolveSibling(id + ".ready.properties"));
            result.put("early_observer", map(ready));
            boolean earlyValid = yes(ready, "positive_before_ok") && yes(ready, "caller_sid_match")
                    && yes(ready, "account_sid_match") && yes(ready, "early_context_verified");
            result.put("early_observer_valid", earlyValid);
            if (!variant.equals("initial-acl")) view.setAcl(List.of(rule));
            List<AclEntry> finalAcl = view.getAcl();
            result.put("final_acl_before_payload", finalAcl.stream().map(Object::toString).toList());
            result.put("final_size_before_payload", file.size());
            boolean strict = finalAcl.size() == 1 && finalAcl.get(0).type() == AclEntryType.ALLOW
                    && finalAcl.get(0).principal().equals(caller) && finalAcl.get(0).flags().isEmpty()
                    && finalAcl.get(0).permissions().containsAll(Set.of(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA));
            boolean safeToWrite = earlyValid && strict && file.size() == 0 && !yes(ready, "early_opened")
                    && Set.of("5", "32").contains(ready.getProperty("early_win32_error"));
            result.put("privacy_gate_before_payload", safeToWrite);
            result.put("final_acl_strict", strict);
            // Controls deliberately use public synthetic bytes to measure retained handles.
            boolean write = earlyValid && (!variant.equals("exclusive-init") || safeToWrite);
            result.put("payload_written", write);
            result.put("candidate_wrote_before_privacy", variant.equals("exclusive-init") && write && !safeToWrite);
            if (write) { ByteBuffer bytes = ByteBuffer.wrap(PAYLOAD); while (bytes.hasRemaining()) file.write(bytes); }
        }
        finally {
            if (observer != null) {
                Files.writeString(signal.resolveSibling(id + ".go"), "closed");
                if (!observer.waitFor(35, TimeUnit.SECONDS)) { observer.destroyForcibly(); observer.waitFor(5, TimeUnit.SECONDS); }
                result.put("observer_exit", observer.isAlive() ? -1 : observer.exitValue());
            }
        }
        Properties end = properties(log.resolve("result.properties"));
        result.put("late_observer", map(end));
        boolean valid = Boolean.TRUE.equals(result.get("early_observer_valid"))
                && yes(end, "positive_after_ok") && yes(end, "late_context_verified")
                && "0".equals(String.valueOf(result.get("observer_exit")));
        result.put("observer_valid", valid);
        result.put("retained_handle_read_payload", yes(end, "retained_matches_payload"));
        result.put("fresh_open_read_payload", yes(end, "fresh_matches_payload"));
        result.put("candidate_private", variant.equals("exclusive-init") && valid
                && Boolean.TRUE.equals(result.get("privacy_gate_before_payload"))
                && !yes(end, "fresh_opened") && "5".equals(end.getProperty("fresh_win32_error"))
                && !yes(end, "retained_matches_payload") && Boolean.TRUE.equals(result.get("payload_written")));
    }

    private static void waitFor(Path marker, Process observer) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25);
        while (!Files.exists(marker)) {
            if (!observer.isAlive() || System.nanoTime() >= deadline) throw new IOException("Observer ready missing");
            Thread.sleep(25);
        }
    }
    private static Properties properties(Path path) throws Exception {
        if (Files.size(path) > 65536) throw new IOException("Observer output exceeds bound");
        Properties value = new Properties();
        try (var reader = Files.newBufferedReader(path)) { value.load(reader); }
        return value;
    }
    private static boolean yes(Properties value, String key) { return "true".equals(value.getProperty(key)); }
    private static Map<String, String> map(Properties value) {
        Map<String, String> result = new TreeMap<>();
        value.forEach((k, v) -> result.put(k.toString(), v.toString())); return result;
    }
    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        if (value instanceof Map<?, ?> map) return "{" + String.join(",", map.entrySet().stream()
                .map(e -> json(e.getKey().toString()) + ":" + json(e.getValue())).toList()) + "}";
        if (value instanceof Collection<?> list) return "[" + String.join(",", list.stream().map(WindowsScratchProbe::json).toList()) + "]";
        StringBuilder result = new StringBuilder("\"");
        for (char c : value.toString().toCharArray()) {
            switch (c) {
                case '"' -> result.append("\\\""); case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n"); case '\r' -> result.append("\\r"); case '\t' -> result.append("\\t");
                default -> { if (c < 32) result.append(String.format("\\u%04x", (int)c)); else result.append(c); }
            }
        }
        return result.append('"').toString();
    }
}
