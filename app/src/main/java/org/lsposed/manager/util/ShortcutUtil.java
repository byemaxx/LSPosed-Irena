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

package org.lsposed.manager.util;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.AdaptiveIconDrawable;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Icon;
import android.graphics.drawable.LayerDrawable;
import android.os.Build;
import android.util.Log;

import org.lsposed.manager.App;
import org.lsposed.manager.R;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public class ShortcutUtil {
    private static final String SHORTCUT_ID = "org.lsposed.manager.shortcut";
    private static final long CALLBACK_TIMEOUT_MILLIS = 5 * 60 * 1000L;

    private static class ShortcutCallback {
        private final IntentSender sender;
        private final Runnable cleanup;

        private ShortcutCallback(IntentSender sender, Runnable cleanup) {
            this.sender = sender;
            this.cleanup = cleanup;
        }
    }

    private static Bitmap getBitmap(Context context, int id) {
        var r = context.getResources();
        var res = r.getDrawable(id, context.getTheme());
        if (res instanceof BitmapDrawable) {
            return ((BitmapDrawable) res).getBitmap();
        } else {
            if (res instanceof AdaptiveIconDrawable) {
                var layers = new Drawable[]{((AdaptiveIconDrawable) res).getBackground(),
                        ((AdaptiveIconDrawable) res).getForeground()};
                res = new LayerDrawable(layers);
            }
            var bitmap = Bitmap.createBitmap(res.getIntrinsicWidth(),
                    res.getIntrinsicHeight(), Bitmap.Config.ARGB_8888);
            var canvas = new Canvas(bitmap);
            res.setBounds(0, 0, canvas.getWidth(), canvas.getHeight());
            res.draw(canvas);
            return bitmap;
        }
    }

    private static Intent getLaunchIntent(Context context) {
        var pm = context.getPackageManager();
        var pkg = context.getPackageName();
        var intent = pm.getLaunchIntentForPackage(pkg);
        if (intent == null) {
            try {
                var pkgInfo = pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES);
                if (pkgInfo.activities != null) {
                    for (var activityInfo : pkgInfo.activities) {
                        if (activityInfo.processName.equals(activityInfo.packageName)) {
                            intent = new Intent(Intent.ACTION_MAIN);
                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                            intent.setComponent(new ComponentName(pkg, activityInfo.name));
                            break;
                        }
                    }
                }
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        if (intent != null) {
            var categories = intent.getCategories();
            if (categories != null) {
                categories.clear();
            }
            intent.addCategory("org.lsposed.manager.LAUNCH_MANAGER");
            intent.setPackage(pkg);
        }
        return intent;
    }

    private static void unregisterReceiver(Context context, BroadcastReceiver receiver, AtomicBoolean unregistered) {
        if (!unregistered.compareAndSet(false, true)) return;
        try {
            context.unregisterReceiver(receiver);
        } catch (IllegalArgumentException e) {
            Log.w(App.TAG, "Shortcut callback receiver was already unregistered", e);
        }
    }

    @SuppressLint("InlinedApi")
    private static ShortcutCallback registerReceiver(Context context, Runnable task) {
        if (task == null) return null;
        var uuid = UUID.randomUUID().toString();
        var filter = new IntentFilter(uuid);
        var unregistered = new AtomicBoolean(false);
        final BroadcastReceiver[] receiverHolder = new BroadcastReceiver[1];
        Runnable cleanup = () -> {
            var receiver = receiverHolder[0];
            if (receiver != null) {
                unregisterReceiver(context, receiver, unregistered);
            }
        };
        var receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent intent) {
                if (!uuid.equals(intent.getAction())) return;
                App.getMainHandler().removeCallbacks(cleanup);
                unregisterReceiver(context, this, unregistered);
                task.run();
            }
        };
        receiverHolder[0] = receiver;
        context.registerReceiver(receiver, filter, null,
                null/* main thread */, Context.RECEIVER_NOT_EXPORTED);
        App.getMainHandler().postDelayed(cleanup, CALLBACK_TIMEOUT_MILLIS);

        var intent = new Intent(uuid).setPackage(context.getPackageName());
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        return new ShortcutCallback(PendingIntent.getBroadcast(context, 0, intent, flags).getIntentSender(),
                cleanup);
    }

    private static ShortcutInfo.Builder getShortcutBuilder(Context context) {
        var builder = new ShortcutInfo.Builder(context, SHORTCUT_ID)
                .setShortLabel(context.getString(R.string.app_name))
                .setIntent(getLaunchIntent(context))
                .setIcon(Icon.createWithAdaptiveBitmap(getBitmap(context,
                        R.drawable.ic_launcher)));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var activity = new ComponentName(context.getPackageName(),
                    "android.app.AppDetailsActivity");
            builder.setActivity(activity);
        }
        return builder;
    }

    public static boolean isRequestPinShortcutSupported(Context context) throws RuntimeException {
        var sm = context.getSystemService(ShortcutManager.class);
        return sm.isRequestPinShortcutSupported();
    }

    public static boolean requestPinLaunchShortcut(Runnable afterPinned) {
        if (!App.isParasitic) throw new RuntimeException();
        var context = App.getInstance();
        var sm = context.getSystemService(ShortcutManager.class);
        if (!sm.isRequestPinShortcutSupported()) return false;
        var callback = registerReceiver(context, afterPinned);
        try {
            var requested = sm.requestPinShortcut(getShortcutBuilder(context).build(),
                    callback == null ? null : callback.sender);
            if (!requested && callback != null) callback.cleanup.run();
            return requested;
        } catch (RuntimeException e) {
            if (callback != null) callback.cleanup.run();
            throw e;
        }
    }

    public static boolean updateShortcut() {
        if (!isLaunchShortcutPinned()) return false;
        var context = App.getInstance();
        var sm = context.getSystemService(ShortcutManager.class);
        List<ShortcutInfo> shortcutInfoList = new ArrayList<>();
        shortcutInfoList.add(getShortcutBuilder(context).build());
        return sm.updateShortcuts(shortcutInfoList);
    }

    public static boolean isLaunchShortcutPinned() {
        var context = App.getInstance();
        var sm = context.getSystemService(ShortcutManager.class);
        for (var info : sm.getPinnedShortcuts()) {
            if (SHORTCUT_ID.equals(info.getId())) {
                return true;
            }
        }
        return false;
    }

}
