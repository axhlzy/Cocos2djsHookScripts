export const HookStringUtils = () => {

    // native\cocos\base\UTF8.cpp
    // ccstd::string getStringUTFCharsJNI(JNIEnv *env, jstring srcjStr, bool *ret)
    A(getExportFromName('_ZN7cocos2d11StringUtils20getStringUTFCharsJNIEP7_JNIEnvP8_jstringPb'), (args, _ctx, pass) => {
        pass.set('args0', args[0])
        pass.set('args1', args[1])
        pass.set('args2', args[2])
        pass.set('args3', args[3])
    }, (ret, _ctx, pass) => {
        const args0 = pass.get('args0')
        const args1 = pass.get('args1')
        const args2 = pass.get('args2')
        const args3 = pass.get('args3')
        LOGD(`${ret} = getStringUTFCharsJNI(env='${args1}', srcjStr='${args2}', ret='${args3}')`)
    })

}

globalThis.HookStringUtils = HookStringUtils

declare global {
    var HookStringUtils: () => void
}
