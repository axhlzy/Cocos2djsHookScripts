export const HookJniHelper = () => {

    // native\cocos\platform\java\jni\JniHelper.cpp
    // bool JniHelper::getStaticMethodInfo(JniMethodInfo &methodinfo, const char *className, const char *methodName, const char *paramCode) {
    A(getExportFromName('_ZN7cocos2d9JniHelper19getStaticMethodInfoERNS_14JniMethodInfo_EPKcS4_S4_'), (args) => {
        LOGD(`JniHelper::getStaticMethodInfo('${args[1]}', '${args[2].readCString()}', '${args[3].readCString()}', '${args[4].readCString()}')`)
    })

}

globalThis.HookJniHelper = HookJniHelper

declare global {
    var HookJniHelper: () => void
}
