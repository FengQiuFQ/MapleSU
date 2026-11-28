package dev.maplesu.manager.runtime;

import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/** Test-APK-only native su probe. Only the target Manager UID may ask it to run. */
final class NativeSuProbe {
    static void run(Service service, Parcel data, Parcel reply) {
        String stage = "caller identity";
        try {
            int manager = service.getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid;
            if (Binder.getCallingUid() != manager) throw new SecurityException("Fixture caller mismatch");
            int mode = data.readInt();
            stage = "mode " + mode;
            Bundle result;
            if (mode == 1) result = terminal(service, manager, null);
            else if (mode == 7) {
                IBinder broker = data.readStrongBinder();
                result = new Bundle();
                if (broker == null) throw new IllegalArgumentException("Fixture discovery absent");
                result.putInt("uid", Process.myUid());
                result.putString("descriptor", broker.getInterfaceDescriptor());
                Parcel query = Parcel.obtain(); Parcel answer = Parcel.obtain();
                try {
                    query.writeInterfaceToken("dev.maplesu.manager.runtime.INativeSuDiscovery");
                    if (!broker.transact(IBinder.FIRST_CALL_TRANSACTION, query, answer, 0))
                        throw new IOException("Discovery transaction rejected");
                    answer.readException();
                    IBinder endpoint = answer.readStrongBinder();
                    result.putBoolean("endpoint", endpoint != null);
                    if (endpoint != null) result.putString("endpointDescriptor", endpoint.getInterfaceDescriptor());
                } finally { query.recycle(); answer.recycle(); }
            }
            else if (mode == 6) {
                /*
                 * E2 third-party session on the *published* restricted binder, from this
                 * fixture's own UID: real stdin, real stdout/stderr, real exit status and
                 * an optional cancel. No PTY, because a terminal is a separate contract.
                 */
                result = session(service, data);
            }
            else if (mode == 5) {
                // The published entry has no fixed path on PATH (zero-mount build), and
                // the old NATIVE_SU_BIND discovery action no longer exists. The
                // instrumentation already holds the published restricted binder, so the
                // fixture receives it and transacts on it as its own UID - which is the
                // identity the Root endpoint must judge.
                IBinder broker = data.readStrongBinder();
                if (broker == null) throw new IllegalArgumentException("Fixture broker absent");
                result = terminal(service, manager, broker);
            }
            else if (mode == 2) {
                String path = executable(data);
                result = cancel(path);
            }
            else if (mode == 3) {
                String path = executable(data);
                String[] arguments = data.createStringArray();
                byte[] input = data.createByteArray();
                if (arguments == null || arguments.length > 16) throw new IllegalArgumentException("Fixture arguments invalid");
                java.util.ArrayList<String> argv = new java.util.ArrayList<>();
                // The client is only reachable at its published absolute path (the
                // directory name is derived, not a constant), so the caller supplies it.
                argv.add(path);
                java.util.Collections.addAll(argv, arguments);
                result = execute(argv, input);
            }
            else {
                String path = executable(data);
                String command = data.readString();
                byte[] input = data.createByteArray();
                result = execute(java.util.Arrays.asList(path, "-c", command), input, mode == 4);
            }
            result.putInt("uid", Process.myUid());
            reply.writeNoException(); reply.writeTypedObject(result, 0);
        } catch (Exception error) {
            StringBuilder detail = new StringBuilder("Native su fixture failed at ").append(stage);
            Throwable cause = error;
            for (int depth = 0; cause != null && depth < 4; depth++, cause = cause.getCause())
                detail.append("; ").append(cause.getClass().getName()).append(": ").append(cause.getMessage());
            throw new IllegalStateException(detail.toString(), error);
        }
    }

    /**
     * P1.su (FIRST_CALL_TRANSACTION + 8): the fixture's own UID asks KernelSU for root
     * the way a legacy third-party app does - it execs the standard su path. The
     * KernelSU sucompat hook decides from the kernel allowlist
     * (`third_party/kernelsu/applied/kernel/feature/sucompat.c:31,186`), so the answer
     * belongs to this fixture's uid, not to the Manager's. This method only reports what
     * that uid observed: started/finished/exit code/stdout/stderr, or the exact
     * exec failure (errno + cause chain) when the entry is not there at all.
     */
    static void suCompat(Service service, Parcel reply) {
        suExec(service, "/system/bin/id -u", reply);
    }

    /** FIRST+11 preserves FIRST+8 and shares the caller's absolute ten-second budget. */
    static void suCompatBefore(Service service, long deadlineNanos, Parcel reply) {
        Bundle result = suCompatBefore(service, deadlineNanos, true);
        reply.writeNoException();
        reply.writeTypedObject(result, 0);
    }

    /** Foreground test APK entry; execution still belongs to this service's real UID. */
    static Bundle suCompatInCurrentProcessBefore(Service service, long deadlineNanos) {
        return suCompatBefore(service, deadlineNanos, false);
    }

    private static Bundle suCompatBefore(Service service, long deadlineNanos, boolean binderCaller) {
        long started = android.os.SystemClock.elapsedRealtimeNanos();
        long deadline = Math.min(deadlineNanos, started + TimeUnit.SECONDS.toNanos(10));
        Bundle result = new Bundle();
        result.putInt("uid", Process.myUid());
        result.putString("path", "/system/bin/su");
        result.putString("command", "/system/bin/id -u");
        result.putLong("deadlineElapsedRealtimeNanos", deadline);
        java.lang.Process process = null;
        ExecutorService readers = null;
        String stage = "caller_identity";
        try {
            if (binderCaller) {
                int manager = service.getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid;
                if (Binder.getCallingUid() != manager) throw new SecurityException("Fixture caller mismatch");
            } else if (service.getApplicationInfo().uid != Process.myUid()) {
                throw new SecurityException("Fixture process identity mismatch");
            }
            remainingSuNanos(deadline);
            stage = "exec";
            process = new ProcessBuilder("/system/bin/su", "-c", "/system/bin/id -u").start();
            result.putBoolean("started", true);
            process.getOutputStream().close();
            final java.lang.Process running = process;
            readers = Executors.newFixedThreadPool(2);
            Future<byte[]> output = readers.submit(() -> read(running.getInputStream()));
            Future<byte[]> error = readers.submit(() -> read(running.getErrorStream()));
            stage = "wait";
            boolean finished = process.waitFor(remainingSuNanos(deadline), TimeUnit.NANOSECONDS);
            result.putBoolean("finished", finished);
            if (!finished) throw new TimeoutException("SU_FIXTURE_DEADLINE_EXCEEDED");
            result.putInt("code", process.exitValue());
            stage = "stdout";
            result.putByteArray("stdout", output.get(remainingSuNanos(deadline), TimeUnit.NANOSECONDS));
            stage = "stderr";
            result.putByteArray("stderr", error.get(remainingSuNanos(deadline), TimeUnit.NANOSECONDS));
            stage = "complete";
        } catch (Exception failure) {
            if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
            result.putString("exception", failure.toString());
            result.putBoolean("timedOut", failure instanceof TimeoutException);
            StringBuilder causes = new StringBuilder();
            for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                if (causes.length() > 0) causes.append(" <- ");
                causes.append(cause);
                if (cause instanceof ErrnoException) {
                    int errno = ((ErrnoException) cause).errno;
                    result.putInt("errno", errno);
                    result.putString("errnoName", Os.strerror(errno));
                }
            }
            result.putString("causes", causes.toString());
        } finally {
            result.putString("stage", stage);
            if (process != null) {
                if (process.isAlive()) process.destroyForcibly();
                long remaining = deadline - android.os.SystemClock.elapsedRealtimeNanos();
                try {
                    if (process.isAlive() && remaining > 0) process.waitFor(remaining, TimeUnit.NANOSECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    result.putString("cleanupFailure", interrupted.toString());
                }
                result.putBoolean("cleanupPending", process.isAlive());
            }
            if (readers != null) {
                readers.shutdownNow();
                long remaining = deadline - android.os.SystemClock.elapsedRealtimeNanos();
                try {
                    boolean terminated = readers.isTerminated() || remaining > 0 &&
                            readers.awaitTermination(remaining, TimeUnit.NANOSECONDS);
                    result.putBoolean("cleanupPending", result.getBoolean("cleanupPending") || !terminated);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    result.putBoolean("cleanupPending", true);
                    result.putString("cleanupFailure", interrupted.toString());
                }
            }
            result.putLong("elapsedNanos", android.os.SystemClock.elapsedRealtimeNanos() - started);
        }
        return result;
    }

    private static long remainingSuNanos(long deadline) throws TimeoutException {
        long remaining = deadline - android.os.SystemClock.elapsedRealtimeNanos();
        if (remaining <= 0) throw new TimeoutException("SU_FIXTURE_DEADLINE_EXCEEDED");
        return remaining;
    }

    /**
     * P1.su domain (FIRST_CALL_TRANSACTION + 9): the same real `su` exec from this
     * fixture's own UID, but the command also prints the **SELinux domain** of the child:
     *
     * <pre>su -c '/system/bin/id -u; cat /proc/self/attr/current'</pre>
     *
     * <p>A uid of 0 is not working root: a su child that stays in the caller's
     * `untrusted_app` domain cannot search the daemon directory and the daemon's own
     * children abort. This transaction exists so the KSU line can record uid **and**
     * domain from one invocation, the same two facts the hook line records.
     */
    static void suDomain(Service service, Parcel reply) {
        suExec(service, "/system/bin/id -u; cat /proc/self/attr/current 2>&1", reply);
    }

    /** Fixed visibility observations from the ordinary fixture UID, never a root shell. */
    static void visibility(Service service, Parcel reply) {
        Bundle result = new Bundle();
        result.putInt("uid", Process.myUid());
        try {
            int manager = service.getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid;
            if (Binder.getCallingUid() != manager) throw new SecurityException("Fixture caller mismatch");
            String path = "/system/bin/su";
            result.putBoolean("exists", new File(path).exists());
            result.putBoolean("executable", new File(path).canExecute());
            try { Os.stat(path); result.putInt("statErrno", 0); }
            catch (ErrnoException error) { result.putInt("statErrno", error.errno); }
            try { Os.lstat(path); result.putInt("lstatErrno", 0); }
            catch (ErrnoException error) { result.putInt("lstatErrno", error.errno); }
            try { result.putString("symlink", Os.readlink(path)); }
            catch (ErrnoException error) { result.putInt("readlinkErrno", error.errno); }
            try (InputStream input = new FileInputStream("/proc/self/mountinfo")) {
                String mounts = new String(read(input), StandardCharsets.UTF_8);
                result.putBoolean("legacyMount", mounts.contains(" - overlay maplesu-su "));
            }
        } catch (Exception error) { result.putString("failure", error.toString()); }
        reply.writeNoException(); reply.writeTypedObject(result, 0);
    }

    /** One real `/system/bin/su -c <command>` from this fixture's own UID. */
    private static void suExec(Service service, String command, Parcel reply) {
        Bundle result = new Bundle();
        result.putInt("uid", Process.myUid());
        result.putString("path", "/system/bin/su");
        result.putString("command", command);
        java.lang.Process process = null;
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            int manager = service.getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid;
            if (Binder.getCallingUid() != manager) throw new SecurityException("Fixture caller mismatch");
            process = new ProcessBuilder("/system/bin/su", "-c", command).start();
            result.putBoolean("started", true);
            final java.lang.Process running = process;
            Future<byte[]> output = workers.submit(() -> read(running.getInputStream()));
            Future<byte[]> error = workers.submit(() -> read(running.getErrorStream()));
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            result.putBoolean("finished", finished);
            if (finished) {
                result.putInt("code", process.exitValue());
                result.putByteArray("stdout", output.get(5, TimeUnit.SECONDS));
                result.putByteArray("stderr", error.get(5, TimeUnit.SECONDS));
            }
        } catch (Throwable failure) {
            result.putBoolean("started", false);
            result.putString("exception", failure.toString());
            result.putString("message", failure.getMessage());
            StringBuilder chain = new StringBuilder();
            Throwable cause = failure;
            for (int depth = 0; cause != null && depth < 5; depth++, cause = cause.getCause()) {
                if (chain.length() > 0) chain.append(" <- ");
                chain.append(cause.getClass().getName());
                if (cause.getMessage() != null) chain.append(": ").append(cause.getMessage());
                if (cause instanceof ErrnoException) {
                    int errno = ((ErrnoException) cause).errno;
                    result.putInt("errno", errno);
                    result.putString("errnoName", Os.strerror(errno));
                }
            }
            result.putString("causes", chain.toString());
        } finally {
            if (process != null) process.destroyForcibly();
            workers.shutdownNow();
        }
        reply.writeNoException();
        reply.writeTypedObject(result, 0);
    }

    /**
     * Reads the client path the caller published. The directory name is derived from
     * the installed credential, so it is not a constant in this fixture; only an
     * absolute path ending in `/su` is accepted.
     */
    private static String executable(Parcel data) {
        String path = data.readString();
        if (path == null || !path.startsWith("/") || !path.endsWith("/su") || path.contains(".."))
            throw new IllegalArgumentException("Fixture executable mismatch");
        return path;
    }

    private static byte[] read(InputStream stream) throws IOException {
        try (InputStream input = stream; ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) >= 0) bytes.write(buffer, 0, count);
            return bytes.toByteArray();
        }
    }
    private static Bundle execute(java.util.List<String> arguments, byte[] input) throws Exception {
        return execute(arguments, input, false);
    }
    private static Bundle execute(java.util.List<String> arguments, byte[] input, boolean terminalEnvironment) throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(3);
        ProcessBuilder builder = new ProcessBuilder(arguments);
        if (terminalEnvironment) {
            builder.environment().put("LD_LIBRARY_PATH", "/maplesu-fixture/lib");
            builder.environment().put("ENV", "/maplesu-fixture/missing-rc");
        }
        java.lang.Process process = builder.start();
        try {
            Future<byte[]> output = workers.submit(() -> read(process.getInputStream()));
            Future<byte[]> error = workers.submit(() -> read(process.getErrorStream()));
            Future<?> writer = workers.submit(() -> {
                try (OutputStream destination = process.getOutputStream()) { destination.write(input); }
                catch (IOException ignored) { /* A denied client closes stdin before it is consumed. */ }
            });
            if (!process.waitFor(15, TimeUnit.SECONDS)) throw new IllegalStateException("su timeout");
            writer.get(5, TimeUnit.SECONDS);
            Bundle result = new Bundle(); result.putInt("code", process.exitValue());
            result.putByteArray("stdout", output.get(5, TimeUnit.SECONDS));
            result.putByteArray("stderr", error.get(5, TimeUnit.SECONDS));
            return result;
        } finally { process.destroyForcibly(); workers.shutdownNow(); }
    }
    private static Bundle cancel(String clientPath) throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(2);
        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
        java.lang.Process process = new ProcessBuilder("/system/bin/sh", "-c",
                "printf '%s\\n' \"$$\" >&2; exec \"$@\"", "su-fixture", clientPath, "-c",
                "printf '%s\\n' \"$$\"; exec /system/bin/sleep 30")
                .redirectOutput(new File("/proc/self/fd/" + pipe[1].getFd())).start();
        pipe[1].close();
        try {
            // Process.destroyForcibly closes its own Java streams. Keep an independent
            // pipe so only the actual root writer's exit can produce EOF here.
            BufferedReader output = new BufferedReader(new InputStreamReader(
                    new ParcelFileDescriptor.AutoCloseInputStream(pipe[0]), StandardCharsets.UTF_8));
            int clientPid = Integer.parseInt(new BufferedReader(new InputStreamReader(
                    process.getErrorStream(), StandardCharsets.UTF_8)).readLine());
            String line = workers.submit(output::readLine).get(5, TimeUnit.SECONDS);
            int pid = Integer.parseInt(line);
            android.os.Process.sendSignal(clientPid, 9);
            if (!process.waitFor(5, TimeUnit.SECONDS)) throw new IllegalStateException("client did not exit");
            Future<Boolean> eof = workers.submit(() -> output.read() == -1);
            Bundle result = new Bundle(); result.putInt("pid", pid); result.putBoolean("eof", eof.get(5, TimeUnit.SECONDS));
            result.putInt("code", process.exitValue());
            return result;
        } finally { process.destroyForcibly(); pipe[0].close(); workers.shutdownNow(); }
    }
    private static void text(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); output.writeInt(bytes.length); output.write(bytes);
    }
    private static IBinder discover(Service service, int managerUid) throws Exception {
        CompletableFuture<IBinder> discovered = new CompletableFuture<>();
        android.content.ServiceConnection connection = new android.content.ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder binder) { discovered.complete(binder); }
            @Override public void onServiceDisconnected(ComponentName name) { }
            @Override public void onNullBinding(ComponentName name) {
                discovered.completeExceptionally(new IOException("Discovery binding absent"));
            }
        };
        Intent intent = new Intent("dev.maplesu.manager.action.NATIVE_SU_PEEK")
            .setComponent(new ComponentName("dev.maplesu.manager", "dev.maplesu.manager.runtime.NativeSuBrokerService"));
        new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
            if (!service.bindService(intent, connection, android.content.Context.BIND_AUTO_CREATE))
                discovered.completeExceptionally(new IOException("Discovery bind rejected"));
        });
        try {
            IBinder broker = discovered.get(10, TimeUnit.SECONDS);
            Parcel query = Parcel.obtain(); Parcel answer = Parcel.obtain();
            try {
                query.writeInterfaceToken("dev.maplesu.manager.runtime.INativeSuDiscovery");
                if (!broker.transact(IBinder.FIRST_CALL_TRANSACTION, query, answer, 0))
                    throw new IOException("Discovery transaction rejected");
                answer.readException();
                IBinder endpoint = answer.readStrongBinder();
                if (endpoint == null) throw new IOException("Root endpoint absent");
                return endpoint;
            } finally { query.recycle(); answer.recycle(); }
        } finally { new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
            try { service.unbindService(connection); } catch (IllegalArgumentException ignored) { }
        }); }
    }
    private static Parcel sessionRequest() {
        Parcel request = Parcel.obtain();
        request.writeInterfaceToken("dev.maplesu.manager.runtime.INativeSuSession");
        return request;
    }

    /**
     * A non-terminal restricted session, driven from this fixture's real UID.
     *
     * <p>Parcel layout: broker binder, command, directory, stdin bytes, environment,
     * flags (bit 0 global mount, bit 1 cancel early), cancel-after-milliseconds.
     *
     * <p>Every stream is a real pipe created here, so the bytes a shell writes and the
     * bytes this fixture writes both cross the Binder boundary the way a real client's
     * would. A refusal is reported as `accepted=false` instead of an exception, because
     * "denied" is a valid, expected answer for an unauthorised caller.
     */
    private static Bundle session(Service service, Parcel data) throws Exception {
        IBinder broker = data.readStrongBinder();
        String command = data.readString();
        String directory = data.readString();
        byte[] input = data.createByteArray();
        String[] environment = data.createStringArray();
        int flags = data.readInt();
        int cancelAfter = data.readInt();
        if (broker == null) throw new IllegalArgumentException("Fixture broker absent");
        if (command == null) throw new IllegalArgumentException("Fixture command absent");
        if (directory == null || !directory.startsWith("/")) directory = "/";
        boolean globalMnt = (flags & 1) != 0;
        boolean cancel = (flags & 2) != 0;

        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        DataOutputStream builder = new DataOutputStream(frame);
        builder.writeInt(0x4d535531);
        builder.writeInt(0);                 // terminals: no PTY on this request
        builder.writeInt(0);                 // targetUid: root
        builder.writeInt(globalMnt ? 1 : 0);
        builder.writeInt(0); builder.writeInt(0); builder.writeInt(0); builder.writeInt(0);
        text(builder, "/system/bin/sh");
        text(builder, directory);
        builder.writeInt(3);
        text(builder, "/system/bin/sh"); text(builder, "-c"); text(builder, command);
        builder.writeInt(environment == null ? 0 : environment.length);
        if (environment != null) for (String entry : environment) text(builder, entry);
        builder.flush();

        Bundle result = new Bundle();
        result.putInt("uid", Process.myUid());
        ParcelFileDescriptor[] inPipe = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor[] outPipe = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor[] errPipe = ParcelFileDescriptor.createPipe();
        IBinder owner = new Binder();
        IBinder session = null;
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Parcel request = Parcel.obtain(); Parcel response = Parcel.obtain();
            try {
                request.writeInterfaceToken("dev.maplesu.manager.runtime.INativeSuService");
                request.writeByteArray(frame.toByteArray());
                request.writeTypedObject(inPipe[0], 0);
                request.writeTypedObject(outPipe[1], 0);
                request.writeTypedObject(errPipe[1], 0);
                request.writeStrongBinder(owner);
                if (!broker.transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0))
                    throw new IllegalStateException("Restricted su start transaction absent");
                try {
                    response.readException();
                } catch (SecurityException denied) {
                    result.putBoolean("accepted", false);
                    result.putString("denial", "SecurityException");
                    // The entry's own refusal token (AUTH_DENIED / AUTH_DISABLED / ...):
                    // without it a refused request is indistinguishable from an
                    // unreachable endpoint in the caller's record.
                    result.putString("denialDetail", denied.getMessage());
                    return result;
                } catch (IllegalStateException refused) {
                    result.putBoolean("accepted", false);
                    result.putString("denial", "IllegalStateException");
                    result.putString("denialDetail", refused.getMessage());
                    return result;
                }
                session = response.readStrongBinder();
                if (session == null) throw new IllegalStateException("Restricted su session absent");
            } finally { request.recycle(); response.recycle(); }
            result.putBoolean("accepted", true);
            // The request is delivered; our copies of the child's ends are no longer needed.
            inPipe[0].close(); outPipe[1].close(); errPipe[1].close();

            Future<byte[]> output = workers.submit(() -> read(new ParcelFileDescriptor.AutoCloseInputStream(outPipe[0])));
            Future<byte[]> error = workers.submit(() -> read(new ParcelFileDescriptor.AutoCloseInputStream(errPipe[0])));
            try (OutputStream keyboard = new ParcelFileDescriptor.AutoCloseOutputStream(inPipe[1])) {
                if (input != null && input.length > 0) { keyboard.write(input); keyboard.flush(); }
            }
            if (cancel && cancelAfter >= 0) Thread.sleep(cancelAfter);
            if (cancel) {
                Parcel cancelRequest = sessionRequest(); Parcel cancelResponse = Parcel.obtain();
                try {
                    if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 4, cancelRequest, cancelResponse, 0))
                        throw new IllegalStateException("Restricted su cancel transaction absent");
                    cancelResponse.readException();
                } finally { cancelRequest.recycle(); cancelResponse.recycle(); }
            }
            long waited = System.currentTimeMillis();
            Parcel waitRequest = sessionRequest(); Parcel waitResponse = Parcel.obtain();
            try {
                waitRequest.writeInt(10_000);
                if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 1, waitRequest, waitResponse, 0))
                    throw new IllegalStateException("Restricted su wait transaction absent");
                waitResponse.readException();
                Bundle exit = waitResponse.readTypedObject(Bundle.CREATOR);
                if (exit == null) throw new IllegalStateException("Restricted su exit absent");
                result.putBoolean("finished", exit.getBoolean("finished"));
                result.putInt("exitCode", exit.getInt("exitCode"));
            } finally { waitRequest.recycle(); waitResponse.recycle(); }
            result.putLong("awaitMillis", System.currentTimeMillis() - waited);
            result.putByteArray("stdout", output.get(10, TimeUnit.SECONDS));
            result.putByteArray("stderr", error.get(10, TimeUnit.SECONDS));
            return result;
        } finally {
            if (session != null) {
                Parcel request = sessionRequest(); Parcel response = Parcel.obtain();
                try {
                    if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 5, request, response, 0))
                        throw new IllegalStateException("Restricted su close transaction absent");
                    response.readException();
                } catch (Exception ignored) {
                    /* A session that already ended may reject close; the result stands. */
                } finally { request.recycle(); response.recycle(); }
            }
            for (ParcelFileDescriptor descriptor : new ParcelFileDescriptor[]{
                    inPipe[0], inPipe[1], outPipe[0], outPipe[1], errPipe[0], errPipe[1]}) {
                try { descriptor.close(); } catch (IOException ignored) { }
            }
            java.lang.ref.Reference.reachabilityFence(owner);
            workers.shutdownNow();
        }
    }
    private static Bundle terminal(Service service, int managerUid, IBinder providedBroker) throws Exception {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        Binder owner = new Binder();
        IBinder session = null;
        try (RandomAccessFile nullFile = new RandomAccessFile("/dev/null", "rw")) {
            IBinder broker = providedBroker != null ? providedBroker : discover(service, managerUid);
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(frame);
            output.writeInt(0x4d535531); output.writeInt(7); output.writeInt(0); output.writeInt(0);
            output.writeInt(25); output.writeInt(80); output.writeInt(0); output.writeInt(0);
            text(output, "/system/bin/sh"); text(output, "/"); output.writeInt(3);
            text(output, "/system/bin/sh"); text(output, "-c");
            text(output, "test -t 0 && test -t 1 && test -t 2 || exit 91; stty size; read line; n=0; " +
                    "while [ \"$(stty size)\" != '35 110' ] && [ $n -lt 50 ]; do n=$((n+1)); sleep 0.1; done; stty size; exit 37");
            output.writeInt(1); text(output, "PATH=/system/bin:/system/xbin"); output.flush();
            Bundle result = new Bundle();
            Parcel request = Parcel.obtain(); Parcel response = Parcel.obtain();
            try (ParcelFileDescriptor stdin = ParcelFileDescriptor.dup(nullFile.getFD());
                 ParcelFileDescriptor stdout = ParcelFileDescriptor.dup(nullFile.getFD());
                 ParcelFileDescriptor stderr = ParcelFileDescriptor.dup(nullFile.getFD())) {
                request.writeInterfaceToken("dev.maplesu.manager.runtime.INativeSuService");
                request.writeByteArray(frame.toByteArray());
                request.writeTypedObject(stdin, 0); request.writeTypedObject(stdout, 0); request.writeTypedObject(stderr, 0);
                request.writeStrongBinder(owner);
                if (!broker.transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0))
                    throw new IllegalStateException("Native su start transaction absent");
                try { response.readException(); }
                catch (SecurityException denied) { result.putInt("code", 77); return result; }
                session = response.readStrongBinder();
                if (session == null) throw new IllegalStateException("Native su session absent");
            } finally { request.recycle(); response.recycle(); }
            ParcelFileDescriptor terminalFd;
            request = sessionRequest(); response = Parcel.obtain();
            try {
                if (!session.transact(IBinder.FIRST_CALL_TRANSACTION, request, response, 0))
                    throw new IllegalStateException("Native su terminal transaction absent");
                response.readException();
                terminalFd = response.readTypedObject(ParcelFileDescriptor.CREATOR);
                if (terminalFd == null) throw new IllegalStateException("Native su PTY absent");
            } finally { request.recycle(); response.recycle(); }
            try (InputStream terminal = new ParcelFileDescriptor.AutoCloseInputStream(terminalFd);
                 OutputStream keyboard = new ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(terminalFd.getFileDescriptor()))) {
                CompletableFuture<Boolean> initial = new CompletableFuture<>();
                Future<byte[]> transcript = worker.submit(() -> {
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
                    try {
                        int count;
                        while ((count = terminal.read(buffer)) >= 0) {
                            bytes.write(buffer, 0, count);
                            if (bytes.toString("UTF-8").contains("25 80")) initial.complete(true);
                        }
                    } catch (IOException ended) { /* PTY returns EIO after the slave closes. */ }
                    initial.complete(false); return bytes.toByteArray();
                });
                if (!initial.get(5, TimeUnit.SECONDS)) throw new IllegalStateException("Initial PTY dimensions absent");
                request = sessionRequest(); response = Parcel.obtain();
                try {
                    request.writeIntArray(new int[]{35, 110, 0, 0});
                    if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 3, request, response, 0))
                        throw new IllegalStateException("Native su resize transaction absent");
                    response.readException();
                } finally { request.recycle(); response.recycle(); }
                keyboard.write("next\n".getBytes(StandardCharsets.UTF_8)); keyboard.flush();
                request = sessionRequest(); response = Parcel.obtain();
                try {
                    request.writeInt(10_000);
                    if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 1, request, response, 0))
                        throw new IllegalStateException("Native su wait transaction absent");
                    response.readException();
                    Bundle exit = response.readTypedObject(Bundle.CREATOR);
                    if (exit == null || !exit.getBoolean("finished")) throw new IllegalStateException("Native su PTY did not exit");
                    result.putInt("code", exit.getInt("exitCode"));
                } finally { request.recycle(); response.recycle(); }
                result.putByteArray("stdout", transcript.get(5, TimeUnit.SECONDS));
                return result;
            }
        } finally {
            try {
                if (session != null) {
                    Parcel request = sessionRequest(); Parcel response = Parcel.obtain();
                    try {
                        if (!session.transact(IBinder.FIRST_CALL_TRANSACTION + 5, request, response, 0))
                            throw new IllegalStateException("Native su close transaction absent");
                        response.readException();
                    } finally { request.recycle(); response.recycle(); }
                }
            } finally {
                java.lang.ref.Reference.reachabilityFence(owner);
                worker.shutdownNow();
            }
        }
    }
}
