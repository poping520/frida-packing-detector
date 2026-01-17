export var FridaPackingDetector;
(function (FridaPackingDetector) {
    class Logger {
        static setEnabled(enabled) {
            Logger.enabled = enabled;
        }
        static print(method, level, args) {
            if (!Logger.enabled)
                return;
            (console[method] ?? console.log)(`[${level}]`, ...args);
        }
        static info(...args) {
            Logger.print("log", "INFO", args);
        }
        static warn(...args) {
            Logger.print("warn", "WARN", args);
        }
        static error(...args) {
            Logger.print("error", "ERROR", args);
        }
    }
    Logger.enabled = false;
    function tryJavaUse(className) {
        try {
            return Java.use(className);
        }
        catch {
            Logger.warn("Can't find class: " + className);
            return null;
        }
    }
    function registerJavaMethodHook(method, callback) {
        if (!method) {
            Logger.warn("Register method hook, method is null");
            return;
        }
        try {
            method.implementation = function (...args) {
                try {
                    callback.onEnter?.call(this, args);
                }
                catch (e) {
                    Logger.warn("JavaMethodHook onEnter error: " + e);
                }
                let retval;
                let thrown;
                try {
                    retval = method.apply(this, args);
                }
                catch (e) {
                    thrown = e;
                }
                try {
                    callback.onLeave?.call(this, args, retval);
                }
                catch (e) {
                    Logger.warn("JavaMethodHook onLeave error: " + e);
                }
                if (thrown) {
                    throw thrown;
                }
                return retval;
            };
        }
        catch (e) {
            Logger.warn(`Register method(${method}) hook error: ${e}`);
        }
    }
    function hookCustomApplication(className, callback) {
        const getLaunchActivityClassName = (context) => {
            const packageName = context.getPackageName();
            const intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            if (intent) {
                return intent.getComponent()?.getClassName();
            }
            return null;
        };
        const getAnyActivityClassName = (context) => {
            // public static final int GET_ACTIVITIES = 0x00000001;
            const packageName = context.getPackageName();
            const array = context.getPackageManager().getPackageInfo(packageName, 0x1).activities;
            if (array && array.value && array.value.length > 0) {
                const activityInfo = array.value[0];
                return activityInfo.name.value;
            }
            return null;
        };
        const Application = tryJavaUse(className);
        if (!Application) {
            callback?.onError?.("Can't find application class: " + className);
            return;
        }
        const hookOnCreate = (className) => {
            registerJavaMethodHook(Application.onCreate, {
                onEnter: function () {
                    if (tryJavaUse(className) != null) {
                        callback?.onUnpacked?.();
                    }
                    else {
                        callback?.onError?.("APK not unpacked yet in Application.onCreate");
                    }
                }
            });
        };
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
                }
                else {
                    // 判定为未加固
                    callback?.onDetected?.(false);
                }
            },
            onLeave: function () {
                if (!this.isPacked)
                    return;
                if (tryJavaUse(this.testActivityClassName) != null) {
                    callback?.onUnpacked?.();
                }
                else {
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
    function register(callback, isLogging) {
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
                    let appInfo = this.getApplicationInfo();
                    if (appInfo.className == null) {
                        // 没有自定义 Application，判定未加固
                        callback?.onDetected?.(false);
                    }
                    else {
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
        });
    }
    FridaPackingDetector.register = register;
})(FridaPackingDetector || (FridaPackingDetector = {}));
