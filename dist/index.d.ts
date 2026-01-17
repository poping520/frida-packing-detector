export declare namespace FridaPackingDetector {
    /**
     * 壳检测回调接口
     */
    interface DetectCallback {
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
    /**
     * 注册加固检测
     *
     * @param callback 回调
     * @param isLogging 是否开启日志
     */
    function register(callback: DetectCallback, isLogging?: boolean): void;
}
