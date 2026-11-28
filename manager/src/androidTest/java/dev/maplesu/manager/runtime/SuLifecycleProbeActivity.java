package dev.maplesu.manager.runtime;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import java.util.concurrent.TimeUnit;

/** Keeps the test caller foreground while its independent service exercises su. */
public final class SuLifecycleProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        captureCurrentDeadline(getIntent());
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        captureCurrentDeadline(intent);
        if (hasWindowFocus()) startProbe();
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (focused) startProbe();
    }

    private void startProbe() {
        Intent intent = getIntent();
        String mode = intent.getStringExtra("mode");
        if (mode != null) {
            intent.removeExtra("mode");
            Intent probe = new Intent(this, SuLifecycleProbeService.class).putExtra("mode", mode);
            if ("current-standard".equals(mode)) {
                probe.putExtra("currentStandardStarted", intent.getLongExtra("currentStandardStarted", 0));
                probe.putExtra("currentStandardDeadline", intent.getLongExtra("currentStandardDeadline", 0));
            }
            startService(probe);
        }
    }

    private void captureCurrentDeadline(Intent intent) {
        if (intent != null && "current-standard".equals(intent.getStringExtra("mode"))) {
            long started = SystemClock.elapsedRealtimeNanos();
            intent.putExtra("currentStandardStarted", started);
            intent.putExtra("currentStandardDeadline", started + TimeUnit.SECONDS.toNanos(10));
        }
    }
}
