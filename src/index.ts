export namespace FridaPackingDetector {

    class Logger {

        private static enabled = false;

        static setEnabled(enabled: boolean) {
            Logger.enabled = enabled;
        }

        private static print(method: "log" | "warn" | "error", level: string, args: unknown[]) {
            if (!Logger.enabled) return;
            (console[method] ?? console.log)(`[${level}]`, ...args);
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

    function hookCustomApplication(className: string, callback: DetectCallback): void {

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

        const Application = tryJavaUse(className);
        if (!Application) {
            callback?.onError?.("Can't find application class: " + className);
            return;
        }

        const hookOnCreate = (className: string): void => {
            registerJavaMethodHook(Application.onCreate, {
                onEnter: function () {
                    if (tryJavaUse(className) != null) {
                        callback?.onUnpacked?.();
                    } else {
                        callback?.onError?.("APK not unpacked yet in Application.onCreate");
                    }
                }
            });
        }

        registerJavaMethodHook(Application.attachBaseContext, {
            onEnter: function (args) {
                this.isPacked = false;

                const context = args[0];
                let testActivityClassName = getLaunchActivityClassName(context);
                if (!testActivityClassName) {
                    testActivityClassName = getAnyActivityClassName(context);
                }

                if (!testActivityClassName) {
                    callback?.onError?.("Can't find any activity class");
                    return;
                }

                this.testActivityClassName = testActivityClassName;

                Logger.info(`Test activity: ${testActivityClassName}`);
                if (tryJavaUse(testActivityClassName) == null) {
                    // 在 Application attachBaseContext 之前
                    // 无法创建 LaunchActivity / AnyActivity 类，判定为加固
                    this.isPacked = true;
                    callback?.onDetected?.(true);
                } else {
                    // 判定为未加固
                    callback?.onDetected?.(false);
                }
            },
            onLeave: function () {
                if (!this.isPacked) return;

                if (tryJavaUse(this.testActivityClassName) != null) {
                    callback?.onUnpacked?.();
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

        Java.perform(function () {

            const LoadedApk = tryJavaUse("android.app.LoadedApk");
            if (!LoadedApk) {
                callback?.onError?.("Can't find class: android.app.LoadedApk");
                return;
            }


            /*
             * class LoadApk:
             *     public Application makeApplication(boolean forceDefaultAppClass, Instrumentation instrumentation);
             *
             *     public ApplicationInfo getApplicationInfo();
             */
            registerJavaMethodHook(LoadedApk.makeApplication, {
                onEnter: function (args) {
                    if (args[1] != null) {
                        // Call from ActivityThread.performLaunchActivity
                        return;
                    }

                    // Call from ActivityThread.handleBindApplication
                    let appInfo = this.getApplicationInfo()
                    if (appInfo.className == null) {
                        // 没有自定义 Application，判定未加固
                        callback?.onDetected?.(false);

                    } else {
                        let appClassName = appInfo.className.value;
                        if (!appClassName) {
                            callback?.onError?.("Application class is null");
                            return;
                        }

                        Logger.info("Application class name: " + appClassName);
                        hookCustomApplication(appClassName, callback);
                    }
                }
            });
        })
    }
}
