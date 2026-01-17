# frida-shell-detector

English | [中文](README_cn.md)

A general-purpose Frida library for runtime protection/packing detection in Android APKs.

- **Generic**: Not targeting any specific vendor or protection solution.
- **Non-signature based**: Does not rely on a protection signature database (no fingerprint matching of specific shell classes/so/strings).
- **Runtime decision**: Determines whether protection exists and when unpacking / original app loading is completed based on runtime load timing and availability behavior.

## Overview

This library hooks key points during Android app startup (e.g. `android.app.LoadedApk.makeApplication`, custom `Application.attachBaseContext/onCreate`, etc.). Early in the application lifecycle, it tries to access the app’s own Activity classes:

- If the launcher Activity (or any Activity) **cannot be loaded via `Java.use()` during `Application.attachBaseContext`**, it usually indicates that classes have not been fully loaded from the original APK/DEX yet, and it tends to be judged as **“protected/packed”**.
- When, at a later time, the Activity classes can be loaded normally, it is considered **“unpacked / original app loaded”**, and `onUnpacked` will be triggered.

> Note: This is a “generic runtime behavior detection approach” and does not guarantee 100% accuracy in all environments (e.g. extreme class loading strategies, multi-process, plugin frameworks, etc.).

## Installation

As a project dependency (development/build time):

```bash
npm i
```

## Build

- **build**: Compile the library to `dist/index.js`
- **test**: Compile the test agent to `dist/test_agent.js`

```bash
npm run build
npm run test
```

## Quick Start (in your Frida Agent)

You can directly refer to `src/test.ts`.

Core API: `FridaShellDetector.register(callback, isLogging?)`

- `callback.onDetected(isProtected)`: Triggered when the protection status is detected (`true` means suspected protection, `false` means not protected)
- `callback.onUnpacked()`: If protection is suspected, triggered later when the original app is detected as loaded / unpacking completed
- `callback.onError(message)`: Triggered when an error occurs

Example (pseudo-code, same structure as `src/test.ts`):

```ts
import { FridaShellDetector } from "./index";

function onAppReady() {
  // Put your business logic here (at this time it is more likely that app classes are reliably accessible)
}

FridaShellDetector.register(
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
      console.error("FridaShellDetector error occurred: " + message);
    },
  }
);
```

## Limitations

- **No shell type identification**: Only performs generic decisions for “suspected protection” and “when unpacking is completed”.
- **Complex app architectures may affect results**: e.g. pluginization, hotfix frameworks, dynamic multi-dex loading, multi-process startup path differences, etc.

## Disclaimer

This project is for security research, compliant testing, and learning/exchange only. Please ensure you use it within the scope of legal authorization.
