export namespace FridaPackingDetector {

    class Logger {

        private static enabled = false;

        static setEnabled(enabled: boolean) {
            Logger.enabled = enabled;
        }

        private static print(method: "log" | "warn" | "error", level: string, args: unknown[]) {
            if (!Logger.enabled) return;
            (console[method] ?? console.log)(`[FridaPackingDetector - ${level}]`, ...args);
        }

        static info(...args: unknown[]) {
            Logger.print("log", "INFO", args);
        }

        static warn(...args: unknown[]) {
            Logger.print("warn", "WARN", args);
        }

        static error(...args: unknown[]) {
            Logger.print("error", "ERROR", args);
        }
    }

    /**
     * 壳检测回调接口
     */
    export interface DetectCallback {

        /**
         * 检测到加固状态时触发
         * @param isProtected - true 表示已加固，false 表示未加固
         */
        onDetected?: (isProtected: boolean) => void;

        /**
         * 壳解包完成、原始应用加载完成时触发
         */
        onUnpacked?: () => void;

        /**
         * 发生错误时触发
         * @param message - 错误信息
         */
        onError?: (message: string) => void;
    }


    function tryJavaUse(className: string): Java.Wrapper | null {
        try {
            return Java.use(className);
        } catch {
            Logger.warn("Can't find class: " + className);
            return null;
        }
    }

    interface JavaMethodHookCallback {

        onEnter?: ((this: Java.Wrapper, args: Java.Wrapper[]) => void) | undefined;

        onLeave?: ((this: Java.Wrapper, args: Java.Wrapper[], retval: Java.Wrapper) => void) | undefined;
    }

    /**
     * Mirrors LoadedApk.makeApplicationInner resolution (Android 13+ / API 33+):
     * ApplicationInfo#getCustomApplicationClassNameForProcess first, else {@link ApplicationInfo#className}.
     * @see https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/app/LoadedApk.java
     */
    function resolveApplicationClassNameFromApplicationInfo(appInfo: Java.Wrapper): string | null {
        try {
            const Process = Java.use("android.os.Process");
            const processName = Process.myProcessName();
            const perProcess = appInfo.getCustomApplicationClassNameForProcess(processName);
            if (perProcess != null) {
                const s = String(perProcess);
                if (s.length > 0) {
                    return s;
                }
            }
        } catch (e) {
            Logger.warn("getCustomApplicationClassNameForProcess failed: " + e);
        }

        try {
            if (appInfo.className != null && appInfo.className.value != null) {
                return appInfo.className.value as string;
            }
        } catch {
            /* ignore */
        }
        return null;
    }

    function registerJavaMethodHook(
        method: Java.Method,
        callback: JavaMethodHookCallback,
    ): void {

        if (!method) {
            Logger.warn("Register method hook, method is null")
            return;
        }

        try {
            method.implementation = function (this: Java.Wrapper, ...args: any[]): any {
                try {
                    callback.onEnter?.call(this, args);
                } catch (e) {
                    Logger.warn("JavaMethodHook onEnter error: " + e);
                }

                let retval: any;
                let thrown: any;

                try {
                    retval = method.apply(this, args);
                } catch (e) {
                    thrown = e;
                }

                try {
                    callback.onLeave?.call(this, args, retval as Java.Wrapper);
                } catch (e) {
                    Logger.warn("JavaMethodHook onLeave error: " + e);
                }

                if (thrown) {
                    throw thrown;
                }
                return retval;
            }
        } catch (e) {
            Logger.warn(`Register method(${method}) hook error: ${e}`);
        }
    }

    function hookCustomApplication(appClassName: string, callback: DetectCallback): void {

        const getLaunchActivityClassName = (context: Java.Wrapper): string | null => {
            const packageName = context.getPackageName();
            const intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            if (intent) {
                return intent.getComponent()?.getClassName();
            }
            return null;
        }

        const getAnyActivityClassName = (context: Java.Wrapper): string | null => {
            // public static final int GET_ACTIVITIES = 0x00000001;
            const packageName = context.getPackageName();
            const array = context.getPackageManager().getPackageInfo(packageName, 0x1).activities;

            if (array && array.value && array.value.length > 0) {
                const activityInfo = array.value[0];
                return activityInfo.name.value;
            }
            return null;
        }

        const Application = tryJavaUse(appClassName);
        if (!Application) {
            callback.onError?.("Can't find application class: " + appClassName);
            return;
        }

        const hookOnCreate = (className: string): void => {
            registerJavaMethodHook(Application.onCreate, {
                onEnter: function () {
                    if (tryJavaUse(className) != null) {
                        Logger.info("Call onUnpacked")
                        callback.onUnpacked?.();
                    } else {
                        callback.onError?.("APK not unpacked yet in Application.onCreate");
                    }
                }
            });
        }

        // Hook Custom Application attachBaseContext
        registerJavaMethodHook(Application.attachBaseContext, {
            onEnter: function (args) {
                this.isPacked = false;

                const context = args[0];
                let testActivityClassName = getLaunchActivityClassName(context);
                if (!testActivityClassName) {
                    testActivityClassName = getAnyActivityClassName(context);
                }

                if (!testActivityClassName) {
                    callback.onError?.("Can't find any activity class");
                    return;
                }

                this.testActivityClassName = testActivityClassName;

                Logger.info(`Test activity: ${testActivityClassName}`);
                // 在 Application attachBaseContext 之前
                // 无法创建 LaunchActivity / AnyActivity 类，判定为加固
                this.isPacked = tryJavaUse(testActivityClassName) == null;

                Logger.info("Call onDetected")
                callback.onDetected?.(this.isPacked);
            },
            onLeave: function () {
                if (!this.isPacked) return;

                if (tryJavaUse(this.testActivityClassName) != null) {
                    Logger.info("Call onUnpacked")
                    callback.onUnpacked?.();
                } else {
                    // hook Application onCreate
                    hookOnCreate(this.testActivityClassName);
                }
            }
        });
    }

    /**
     * 注册加固检测
     *
     * @param callback 回调
     * @param isLogging 是否开启日志
     */
    export function register(callback: DetectCallback, isLogging?: boolean) {
        if (isLogging) {
            Logger.setEnabled(true);
        }

        const onEnterMakeApplication = function (this: Java.Wrapper) {
            if ((callback as any)["__makeApplication_once__"]) {
                return;
            }
            (callback as any)["__makeApplication_once__"] = true;

            const appInfo = this.getApplicationInfo();
            const appClassName = resolveApplicationClassNameFromApplicationInfo(appInfo);

            if (appClassName == null) {
                callback.onDetected?.(false);
                return;
            }

            Logger.info("Application class name: " + appClassName);
            hookCustomApplication(appClassName, callback);
        };

        // ENTRY
        Java.perform(function () {
            const LoadedApk = tryJavaUse("android.app.LoadedApk");
            if (!LoadedApk) {
                callback.onError?.("Can't find class: android.app.LoadedApk");
                return;
            }

            try {
                // From Android 13 (API 33), ActivityThread binds the app via
                // LoadedApk#makeApplicationInner(boolean, Instrumentation), not makeApplication().
                if (LoadedApk.makeApplicationInner) {
                    const overload = LoadedApk.makeApplicationInner.overload("boolean", "android.app.Instrumentation");
                    registerJavaMethodHook(overload, {onEnter: onEnterMakeApplication});
                    Logger.info("Hooked LoadedApk.makeApplicationInner(boolean, Instrumentation)");
                    return;
                }
            } catch (e) {
                Logger.warn("makeApplicationInner hook failed, will try makeApplication: " + e);
            }

            // Hook makeApplication
            if (LoadedApk.makeApplication) {
                registerJavaMethodHook(LoadedApk.makeApplication, {onEnter: onEnterMakeApplication});
                Logger.info("Hooked LoadedApk.makeApplication(boolean, Instrumentation)");
                return;
            }

            callback.onError?.(
                "Can't find method: android.app.LoadedApk.makeApplication (and makeApplicationInner unavailable)",
            );
        });
    }
}
