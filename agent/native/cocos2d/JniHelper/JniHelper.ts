import { getExportFromName as GF } from "../../../utils/cocos"

export const HookJniHelper = () => {
    // Hook_getStaticMethodInfo()
    Hook_callStaticVoidMethod()
}

const Hook_getStaticMethodInfo = () => {
    // native\cocos\platform\java\jni\JniHelper.cpp
    // bool JniHelper::getStaticMethodInfo(JniMethodInfo &methodinfo, const char *className, const char *methodName, const char *paramCode) {
    A(GF('_ZN7cocos2d9JniHelper19getStaticMethodInfoERNS_14JniMethodInfo_EPKcS4_S4_'), (args) => {
        LOGD(`JniHelper::getStaticMethodInfo('${args[1]}', '${args[2].readCString()}', '${args[3].readCString()}', '${args[4].readCString()}')`)
    })
}

const Hook_callStaticVoidMethod = () => {
    // native\cocos\platform\java\jni\JniHelper.cpp
    // void JniHelper::callStaticVoidMethod(const char *className, const char *methodName, const char *paramCode, ...) {
    A(GF('_ZN7cocos2d9JniHelper20callStaticVoidMethodIJNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEES8_EEEvRKS8_SA_DpT_'), (args) => {
        LOGD(hexdump(args[1]))
        LOGD(hexdump(args[2]))
        LOGD(hexdump(args[3]))
        LOGD(`JniHelper::callStaticVoidMethod('${args[0]}', '${args[1].readCString()}', '${args[2].readCString()}', '${args[3].readCString()}')`)
    })
}

globalThis.HookJniHelper = HookJniHelper

declare global {
    var HookJniHelper: () => void
}
