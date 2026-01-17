"use strict";
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FridaPackingDetector = void 0;
var FridaPackingDetector;
(function (FridaPackingDetector) {
    var Logger = /** @class */ (function () {
        function Logger() {
        }
        Logger.setEnabled = function (enabled) {
            Logger.enabled = enabled;
        };
        Logger.print = function (method, level, args) {
            var _a;
            if (!Logger.enabled)
                return;
            ((_a = console[method]) !== null && _a !== void 0 ? _a : console.log).apply(void 0, __spreadArray(["[".concat(level, "]")], args, false));
        };
        Logger.info = function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            Logger.print("log", "INFO", args);
        };
        Logger.warn = function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            Logger.print("warn", "WARN", args);
        };
        Logger.error = function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            Logger.print("error", "ERROR", args);
        };
        Logger.enabled = false;
        return Logger;
    }());
    function tryJavaUse(className) {
        try {
            return Java.use(className);
        }
        catch (_a) {
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
            method.implementation = function () {
                var _a, _b;
                var args = [];
                for (var _i = 0; _i < arguments.length; _i++) {
                    args[_i] = arguments[_i];
                }
                try {
                    (_a = callback.onEnter) === null || _a === void 0 ? void 0 : _a.call(this, args);
                }
                catch (e) {
                    Logger.warn("JavaMethodHook onEnter error: " + e);
                }
                var retval;
                var thrown;
                try {
                    retval = method.apply(this, args);
                }
                catch (e) {
                    thrown = e;
                }
                try {
                    (_b = callback.onLeave) === null || _b === void 0 ? void 0 : _b.call(this, args, retval);
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
            Logger.warn("Register method(".concat(method, ") hook error: ").concat(e));
        }
    }
    function hookCustomApplication(className, callback) {
        var _a;
        var getLaunchActivityClassName = function (context) {
            var _a;
            var packageName = context.getPackageName();
            var intent = context.getPackageManager().getLaunchIntentForPackage(packageName);
            if (intent) {
                return (_a = intent.getComponent()) === null || _a === void 0 ? void 0 : _a.getClassName();
            }
            return null;
        };
        var getAnyActivityClassName = function (context) {
            // public static final int GET_ACTIVITIES = 0x00000001;
            var packageName = context.getPackageName();
            var array = context.getPackageManager().getPackageInfo(packageName, 0x1).activities;
            if (array && array.value && array.value.length > 0) {
                var activityInfo = array.value[0];
                return activityInfo.name.value;
            }
            return null;
        };
        var Application = tryJavaUse(className);
        if (!Application) {
            (_a = callback === null || callback === void 0 ? void 0 : callback.onError) === null || _a === void 0 ? void 0 : _a.call(callback, "Can't find application class: " + className);
            return;
        }
        var hookOnCreate = function (className) {
            registerJavaMethodHook(Application.onCreate, {
                onEnter: function () {
                    var _a, _b;
                    if (tryJavaUse(className) != null) {
                        (_a = callback === null || callback === void 0 ? void 0 : callback.onUnpacked) === null || _a === void 0 ? void 0 : _a.call(callback);
                    }
                    else {
                        (_b = callback === null || callback === void 0 ? void 0 : callback.onError) === null || _b === void 0 ? void 0 : _b.call(callback, "Shell not unpacked yet in Application.onCreate");
                    }
                }
            });
        };
        registerJavaMethodHook(Application.attachBaseContext, {
            onEnter: function (args) {
                var _a, _b, _c;
                this.isPacked = false;
                var context = args[0];
                var testActivityClassName = getLaunchActivityClassName(context);
                if (!testActivityClassName) {
                    testActivityClassName = getAnyActivityClassName(context);
                }
                if (!testActivityClassName) {
                    (_a = callback === null || callback === void 0 ? void 0 : callback.onError) === null || _a === void 0 ? void 0 : _a.call(callback, "Can't find any activity class");
                    return;
                }
                this.testActivityClassName = testActivityClassName;
                Logger.info("Test activity: ".concat(testActivityClassName));
                if (tryJavaUse(testActivityClassName) == null) {
                    // 在 Application attachBaseContext 之前
                    // 无法创建 LaunchActivity / AnyActivity 类，判定为加固
                    this.isPacked = true;
                    (_b = callback === null || callback === void 0 ? void 0 : callback.onDetected) === null || _b === void 0 ? void 0 : _b.call(callback, true);
                }
                else {
                    // 判定为未加固
                    (_c = callback === null || callback === void 0 ? void 0 : callback.onDetected) === null || _c === void 0 ? void 0 : _c.call(callback, false);
                }
            },
            onLeave: function () {
                var _a;
                if (!this.isPacked)
                    return;
                if (tryJavaUse(this.testActivityClassName) != null) {
                    (_a = callback === null || callback === void 0 ? void 0 : callback.onUnpacked) === null || _a === void 0 ? void 0 : _a.call(callback);
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
            var _a;
            var LoadedApk = tryJavaUse("android.app.LoadedApk");
            if (!LoadedApk) {
                (_a = callback === null || callback === void 0 ? void 0 : callback.onError) === null || _a === void 0 ? void 0 : _a.call(callback, "Can't find class: android.app.LoadedApk");
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
                    var _a, _b;
                    if (args[1] != null) {
                        // Call from ActivityThread.performLaunchActivity
                        return;
                    }
                    // Call from ActivityThread.handleBindApplication
                    var appInfo = this.getApplicationInfo();
                    if (appInfo.className == null) {
                        // 没有自定义 Application，判定未加固
                        (_a = callback === null || callback === void 0 ? void 0 : callback.onDetected) === null || _a === void 0 ? void 0 : _a.call(callback, false);
                    }
                    else {
                        var appClassName = appInfo.className.value;
                        if (!appClassName) {
                            (_b = callback === null || callback === void 0 ? void 0 : callback.onError) === null || _b === void 0 ? void 0 : _b.call(callback, "Application class is null");
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
})(FridaPackingDetector || (exports.FridaPackingDetector = FridaPackingDetector = {}));
