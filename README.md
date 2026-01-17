# frida-packing-detector

English | [中文](README_cn.md)

A general-purpose Frida library for runtime detection of Android app protection/packing.

- **Generic**: not targeting any specific vendor or protection scheme.
- **Non-signature-based**: does not rely on a protection signature database (no fingerprint matching for specific packer classes/so files/strings).
- **Runtime decision**: determines whether protection exists and when unpacking / original app loading is completed based on runtime loading order and availability behavior.

## Quick start (in your Frida Agent)

Install the dependency in your project:
```bash
npm i frida-packing-detector
```

API: `FridaPackingDetector.register(callback, isLogging?)`

- `callback.onDetected(isProtected)`: triggered when protection status is detected (`true` means protected/packed, `false` means not protected)
- `callback.onUnpacked()`: if protected/packed, triggered later when the original app is detected as loaded / unpacking completed
- `callback.onError(message)`: triggered when an error occurs

Example:

```ts
import {FridaPackingDetector} from "frida-packing-detector";

function onAppReady() {
  // Put your business logic here (at this time app classes should be stably accessible)
}

FridaPackingDetector.register(
  {
    onDetected(isProtected) {
      console.log("Protection detected: " + isProtected);
      if (!isProtected) {
        onAppReady();
      }
    },
    onUnpacked() {
      onAppReady();
    },
    onError(message) {
      console.error("FridaPackingDetector error occurred: " + message);
    },
  }
);
```

## Overview

This library hooks key points in the Android app startup process (e.g. `android.app.LoadedApk.makeApplication`, custom `Application.attachBaseContext/onCreate`, etc.). Early in the app lifecycle, it tries to access the app’s own Activity classes:

- **If, during `Application.attachBaseContext`, the app’s launch Activity (or any Activity) cannot be `Java.use()`’d**, it usually means the original APK/DEX classes have not been fully loaded yet, and the app is considered “protected/packed”.
- **When, at a later time, the Activity classes can be loaded normally**, it is considered “unpacked / original app loaded”, and `onUnpacked` is triggered.

> Note: this is a “generic runtime behavior detection approach” and is not guaranteed to be 100% accurate in all environments (e.g. extreme class-loading strategies, multi-process apps, plugin frameworks, etc.).

## Limitations

- **No packer type identification**: only provides a generic decision for “protected/packed” and “when unpacking is completed”.
- **Complex app architectures may affect results**: e.g. pluginization, hotfix frameworks, dynamic multi-dex loading, differences in multi-process startup paths, etc.

## Disclaimer

This project is for security research, compliant testing, and learning/exchange only. Please ensure you use it within the scope of legal authorization.
