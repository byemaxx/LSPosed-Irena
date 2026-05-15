/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

package org.lsposed.lspd.service;

import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_CRASHED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_MOUNT_FAILED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_OK;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_SELINUX_PERMISSIVE;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_SEPOLICY_INCORRECT;

import android.net.LocalServerSocket;
import android.os.Build;
import android.os.FileObserver;
import android.os.Process;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

@RequiresApi(Build.VERSION_CODES.Q)
public class Dex2OatService implements Runnable {
    private static final String TAG = "LSPosedDex2Oat";
    private static final String WRAPPER32 = "bin/dex2oat32";
    private static final String WRAPPER64 = "bin/dex2oat64";
    private static final String PRELOAD32 = "lib/libpreload32.so";
    private static final String PRELOAD64 = "lib/libpreload64.so";

    private final String[] dex2oatArray = new String[4];
    private final FileDescriptor[] fdArray = new FileDescriptor[6];
    private final FileObserver selinuxObserver;
    private final Object stateLock = new Object();
    private LocalServerSocket serverSocket;
    private boolean running;
    private int compatibility = DEX2OAT_OK;

    private boolean openPreload(int id, String path) {
        try {
            var fd = Os.open(path, OsConstants.O_RDONLY, 0);
            fdArray[id] = fd;
            return true;
        } catch (ErrnoException ignored) {
            return false;
        }
    }

    private boolean openDex2oat(int id, String path) {
        try {
            var fd = Os.open(path, OsConstants.O_RDONLY, 0);
            dex2oatArray[id] = path;
            fdArray[id] = fd;
            return true;
        } catch (ErrnoException ignored) {
            return false;
        }
    }

    public Dex2OatService() {
        var enforce = Paths.get("/sys/fs/selinux/enforce");
        var policy = Paths.get("/sys/fs/selinux/policy");
        var list = new ArrayList<File>();
        list.add(enforce.toFile());
        list.add(policy.toFile());
        selinuxObserver = new FileObserver(list, FileObserver.CLOSE_WRITE) {
            @Override
            public synchronized void onEvent(int i, @Nullable String s) {
                Log.d(TAG, "SELinux status changed");
                if (compatibility == DEX2OAT_CRASHED) {
                    stopWatching();
                    return;
                }

                boolean enforcing = false;
                try (var is = Files.newInputStream(enforce)) {
                    enforcing = is.read() == '1';
                } catch (IOException ignored) {
                }

                synchronized (stateLock) {
                    if (!enforcing) {
                        if (compatibility == DEX2OAT_OK) doMount(false);
                        compatibility = DEX2OAT_SELINUX_PERMISSIVE;
                    } else if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0",
                            "u:object_r:dex2oat_exec:s0", "file", "execute")
                            || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0",
                            "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
                        if (compatibility == DEX2OAT_OK) doMount(false);
                        compatibility = DEX2OAT_SEPOLICY_INCORRECT;
                    } else if (compatibility != DEX2OAT_OK) {
                        if (!ensureMountedLocked()) {
                            stopWatching();
                        } else {
                            compatibility = DEX2OAT_OK;
                        }
                    }
                }
            }

            @Override
            public void stopWatching() {
                super.stopWatching();
                Log.w(TAG, "SELinux observer stopped");
            }
        };
    }

    private String[] dex2oatCandidates() {
        var paths = new String[4];
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
            paths[Process.is64Bit() ? 2 : 0] = "/apex/com.android.runtime/bin/dex2oat";
            paths[Process.is64Bit() ? 3 : 1] = "/apex/com.android.runtime/bin/dex2oatd";
        } else {
            paths[0] = "/apex/com.android.art/bin/dex2oat32";
            paths[1] = "/apex/com.android.art/bin/dex2oatd32";
            paths[2] = "/apex/com.android.art/bin/dex2oat64";
            paths[3] = "/apex/com.android.art/bin/dex2oatd64";
        }
        return paths;
    }

    private void reopenDex2OatStateLocked() {
        var paths = dex2oatCandidates();
        for (int i = 0; i < paths.length; i++) {
            if (paths[i] != null) openDex2oat(i, paths[i]);
        }
        openPreload(4,"/data/adb/modules/zygisk_lsposed/lib/libpreload32.so");
        openPreload(5,"/data/adb/modules/zygisk_lsposed/lib/libpreload64.so");
    }

    private void closeDex2OatStateLocked() {
        for (int i = 0; i < fdArray.length; i++) {
            var fd = fdArray[i];
            if (fd != null) {
                try {
                    Os.close(fd);
                } catch (ErrnoException e) {
                    Log.w(TAG, "Failed to close stale dex2oat fd[" + i + "]", e);
                }
            }
            fdArray[i] = null;
            if (i < dex2oatArray.length) dex2oatArray[i] = null;
        }
    }

    private boolean sameFile(FileDescriptor fd, String path) {
        try {
            var fdStat = Os.fstat(fd);
            var pathStat = Os.stat(path);
            return fdStat.st_dev == pathStat.st_dev && fdStat.st_ino == pathStat.st_ino;
        } catch (ErrnoException ignored) {
            return false;
        }
    }

    private boolean validateOriginalDex2OatFdLocked() {
        for (int i = 0; i < dex2oatArray.length; i++) {
            var fd = fdArray[i];
            if (fd == null) continue;
            if (sameFile(fd, i < 2 ? WRAPPER32 : WRAPPER64)) {
                Log.e(TAG, "dex2oat fd[" + i + "] points to LSPosed wrapper");
                compatibility = DEX2OAT_MOUNT_FAILED;
                return false;
            }
        }
        return true;
    }

    private void clearDex2OatMountsLocked() {
        var paths = dex2oatCandidates();
        doMountNative(false, paths[0], paths[1], paths[2], paths[3]);
    }

    private boolean resetDex2OatStateLocked(boolean clearMounts) {
        if (clearMounts) clearDex2OatMountsLocked();
        closeDex2OatStateLocked();
        reopenDex2OatStateLocked();
        if (validateOriginalDex2OatFdLocked()) return true;
        if (!clearMounts) return resetDex2OatStateLocked(true);
        closeDex2OatStateLocked();
        return false;
    }

    private boolean notMounted() {
        for (int i = 0; i < dex2oatArray.length; i++) {
            var bin = dex2oatArray[i];
            if (bin == null) continue;
            try {
                var apex = Os.stat("/proc/1/root" + bin);
                var wrapper = Os.stat(i < 2 ? WRAPPER32 : WRAPPER64);
                if (apex.st_dev != wrapper.st_dev || apex.st_ino != wrapper.st_ino) {
                    Log.w(TAG, "Check mount failed for " + bin);
                    return true;
                }
            } catch (ErrnoException e) {
                Log.e(TAG, "Check mount failed for " + bin, e);
                return true;
            }
        }
        Log.d(TAG, "Check mount succeeded");
        return false;
    }

    private void doMount(boolean enabled) {
        doMountNative(enabled, dex2oatArray[0], dex2oatArray[1], dex2oatArray[2], dex2oatArray[3]);
    }

    private boolean ensureMountedLocked() {
        if (!notMounted()) return true;
        doMount(true);
        if (notMounted()) {
            doMount(false);
            compatibility = DEX2OAT_MOUNT_FAILED;
            return false;
        }
        return true;
    }

    public void start() {
        synchronized (stateLock) {
            if (running) {
                Log.d(TAG, "Dex2oat wrapper daemon already running");
                return;
            }
            if (!resetDex2OatStateLocked(false)) return;
            if (!ensureMountedLocked()) return;

            running = true;
            var thread = new Thread(this);
            thread.setName("dex2oat");
            thread.start();
            selinuxObserver.startWatching();
            selinuxObserver.onEvent(0, null);
        }
    }

    public void refreshMount() {
        boolean shouldStart;
        synchronized (stateLock) {
            shouldStart = !running;
            if (running && compatibility == DEX2OAT_OK) ensureMountedLocked();
        }
        if (shouldStart) start();
    }

    @Override
    public void run() {
        Log.i(TAG, "Dex2oat wrapper daemon start");
        var sockPath = getSockPath();
        Log.d(TAG, "wrapper path: " + sockPath);
        var lsposed_file = "u:object_r:lsposed_file:s0";
        var dex2oat_exec = "u:object_r:dex2oat_exec:s0";
        var system_file = "u:object_r:system_file:s0";
        SELinux.setFileContext(PRELOAD32, system_file);
        SELinux.setFileContext(PRELOAD64, system_file);
        if (SELinux.checkSELinuxAccess("u:r:dex2oat:s0", dex2oat_exec,
                "file", "execute_no_trans")) {
            SELinux.setFileContext(WRAPPER32, dex2oat_exec);
            SELinux.setFileContext(WRAPPER64, dex2oat_exec);
            setSockCreateContext("u:r:dex2oat:s0");
        } else {
            SELinux.setFileContext(WRAPPER32, lsposed_file);
            SELinux.setFileContext(WRAPPER64, lsposed_file);
            setSockCreateContext("u:r:installd:s0");
        }
        try (var server = new LocalServerSocket(sockPath)) {
            synchronized (stateLock) {
                serverSocket = server;
            }
            setSockCreateContext(null);
            while (running) {
                try (var client = server.accept();
                     var is = client.getInputStream();
                     var os = client.getOutputStream()) {
                    var id = is.read();
                    if (id >= 0 && id < fdArray.length && fdArray[id] != null) {
                        var fd = new FileDescriptor[]{fdArray[id]};
                        client.setFileDescriptorsForSend(fd);
                        os.write(1);
                        Log.d(TAG, "Sent stock fd: is64 = " + ((id & 0b10) != 0) +
                                ", isDebug = " + ((id & 0b01) != 0));
                    } else {
                        Log.w(TAG, "Invalid dex2oat fd request: " + id);
                        os.write(0);
                    }
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Dex2oat wrapper daemon crashed", e);
            setSockCreateContext(null);
            synchronized (stateLock) {
                running = false;
                serverSocket = null;
            }
            if (compatibility == DEX2OAT_OK) {
                doMount(false);
                compatibility = DEX2OAT_CRASHED;
            }
        } finally {
            synchronized (stateLock) {
                if (serverSocket != null) {
                    try {
                        serverSocket.close();
                    } catch (IOException ignored) {
                    }
                    serverSocket = null;
                }
                running = false;
            }
        }
    }

    public int getCompatibility() {
        return compatibility;
    }

    private native void doMountNative(boolean enabled,
                                      String r32, String d32, String r64, String d64);

    private static native boolean setSockCreateContext(@Nullable String context);

    private native String getSockPath();
}
