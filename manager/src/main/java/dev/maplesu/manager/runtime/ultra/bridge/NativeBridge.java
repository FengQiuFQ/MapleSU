package dev.maplesu.manager.runtime.ultra.bridge;

public final class NativeBridge {
    public static native String modulePolicySettings(int requested);
    public static native String publishPolicyBackend(String sha256, byte[] verifiedBytes);
    static {
        String bootLibrary = System.getProperty("maplesu.ultra.boot.library");
        if (bootLibrary != null && android.os.Process.myUid() == 0) {
            System.load(bootLibrary);
        } else {
            System.loadLibrary("maplesu_ultra_bridge");
        }
    }

    private NativeBridge() {}

    public static native String invokeWithDeadline(String operation, long deadlineNanos,
        java.util.concurrent.Callable<String> callback);

    public static native String invokeWithLegacyCredential(String operation, String credential,
        java.util.concurrent.Callable<String> callback);

    public static native String installEnvironment(String insMode, String insExploitMethod);
    public static native String uninstallEnvironment();
    public static native String getEnvironmentState();
    public static native String getInstalledEnvironmentVersion();
    public static native String getSdkVersion();
    public static native String[] captureModuleEnvironment();

    public static native String getSdkBuildIdentity();

    public static native String getSystemStatusJson();

    public static native String testRoot();
    public static native String queryManagerOwnerIdentity();
    public static native String claimManagerIdentity();
    public static native String probeManagerOwnerRoot();
    public static native String runRootCmd(String cmd);
    public static native String readInstalledHelper(String helperPath, int timeoutMillis);

    public static native String addSuAuth(String appPackageName);
    public static native String refreshSuAuthList();
    public static native String removeSuAuth(String modUuid);
    public static native String getSuAuthList();
    public static native String clearSuAuthList();
    public static native String setSuUidProfile(int uid, String packageName, boolean allow);
    public static native String getSuUidProfiles();
    public static native String getSuRuntimeStatus();

    public static native String installModule(String zipFilePath, boolean isDevRunOnceMode);
    public static native String uninstallModule(String modUuid);
    public static native String getModuleList();
    public static native String parseModuleDescriptor(String zipFilePath);

    public static native String getModuleControlCapabilities();
    public static native String getModuleControl(String id32);
    public static native String setModuleEnabled(String id32, boolean enabled);

    public static native String openModuleWebUi(String modUuid);

    public static native String setBootFailProtectEnabled(boolean enable);
    public static native String isBootFailProtectEnabled();

    public static native String setAdbForcedDisabled(boolean enable);
    public static native String isAdbForcedDisabled();

    public static native String testBasics(String item);
    public static native String testDefaultModule(String name);
    public static native String restartZygote64();

    public static native String setLogEnabled(boolean enable);
    public static native String isLogEnabled();
    public static native String readLog();
    public static native String clearLog();

    public static native String oneplusBypassWriteStage1();
    public static native String oneplusBypassIsWorkNormal();

    public static native String parasitePrecheckApp(String targetPidCmdline);
    public static native String parasiteImplantApp(String targetPidCmdline, String soPath);
    public static native String parasiteImplantSuEnv(String targetPidCmdline, String soPath, String suDir);
}
