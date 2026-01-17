# frida-shell-detector
 
[English](README.md) | 中文
 
APK 运行时加固/加壳检测的通用 Frida 库。

- **通用性**：不针对任何特定厂商/特定加固方案。
- **非特征化**：不依赖加固特征库（不做特定壳的 class/so/字符串指纹匹配）。
- **运行时判定**：通过运行时装载时序/可用性行为来判断“是否存在加固”以及“何时完成解包/原始应用加载完成”。

## 原理概述

该库通过 Hook Android 应用启动过程中的关键点（`android.app.LoadedApk.makeApplication`、自定义 `Application.attachBaseContext/onCreate` 等），在应用生命周期早期尝试访问应用自身的 Activity 类：

- **如果在 `Application.attachBaseContext` 阶段无法 `Java.use()` 到应用的启动 Activity（或任意 Activity）**，通常意味着类尚未由原始 APK/DEX 完整加载，倾向判定为“存在加固/加壳”。
- **当后续某个时刻 Activity 类可被正常加载**，则认为“解包完成/原始应用加载完成”，触发 `onUnpacked`。

> 注意：这是一种“通用运行时行为检测思路”，并不承诺对所有环境 100% 准确（例如极端的类加载策略/多进程/插件化框架等）。

## 安装

作为项目依赖（开发/编译时）：

```bash
npm i
```

## 构建

- **build**：编译库到 `dist/index.js`
- **test**：编译测试 Agent 到 `dist/test_agent.js`

```bash
npm run build
npm run test
```

## 快速使用（在你的 Frida Agent 中）

你可以直接参考 `src/test.ts`。

核心 API：`FridaShellDetector.register(callback, isLogging?)`

- `callback.onDetected(isProtected)`：检测到加固状态时触发（`true` 表示疑似加固，`false` 表示未加固）
- `callback.onUnpacked()`：疑似加固时，后续检测到原始应用已加载/解包完成时触发
- `callback.onError(message)`：发生错误时触发

示例（伪代码，结构与 `src/test.ts` 一致）：

```ts
import { FridaShellDetector } from "./index";

function onAppReady() {
  // 在这里写你的业务逻辑（此时更可能已经能稳定访问到应用类）
}

FridaShellDetector.register(
  {
    onDetected(isProtected) {
      console.log("检测到加固情况：" + isProtected);
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

## 局限性

- **不做壳类型识别**：只做“是否疑似加固”与“何时解包完成”的通用判断。
- **复杂应用形态可能影响结果**：例如插件化/热修复/多 dex 动态加载/多进程启动路径差异等。


## 免责声明

本项目仅用于安全研究、合规测试与学习交流。请确保在合法授权范围内使用。
