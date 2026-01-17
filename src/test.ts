import {FridaPackingDetector} from "./index";


function main() {

    function testLoadClass() {
        try {
            let AppCompatActivity = Java.use("androidx.appcompat.app.AppCompatActivity");
            console.log(`Class loaded: ${AppCompatActivity}\n`);
        } catch (e) {
            console.error(`Class not find: ${e}\n`);
        }
    }

    function onAppReady() {
        testLoadClass();
        // ...
    }

    FridaPackingDetector.register({
        onDetected: function (isProtected) {
            console.log(`检测到加固情况：${isProtected}\n`);
            if (isProtected) {
                // APK有加固，这里尝试加载一个类，肯定会失败
                testLoadClass();
            } else {
                // APK没有加固，直接处理你的业务
                onAppReady();
            }
        },
        onUnpacked: function () {
            // APK有加固，此时原始程序已经解包落地，在这里处理你的业务
            onAppReady();
        },
        onError: function (message) {
            console.error("FridaShellDetector error occurred: " + message);
        }
    });
}


setImmediate(main)