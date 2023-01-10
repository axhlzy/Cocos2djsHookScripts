import { soName } from "../../../utils/cocos"
import StdString from "../../../utils/std/std_string"

export const HookevalString = () => {
    // try {
    Hook_evalString_native()
    // } catch {
    //     Hook_evalString_java()
    // }
    // Hook_evalString_java()
}

const Hook_evalString_java = () => {
    Java.perform(() => {
        // public static native int evalString(String str)
        const evalString = Java.use("org.cocos2dx.lib.JavascriptJavaBridge").evalString
        evalString.implementation = function (str: string) {
            LOGD(`[+] evalString: ${str}`)
            return this.evalString(str)
        }
    })
}

const Hook_evalString_native = () => {
    A(getExportFromName('_ZN2se12ScriptEngine10evalStringEPKciPNS_5ValueES2_'),
        (args) => LOGD(`[+] evalString: |${args[1].readCString()}|`))
}





function todo() {
    // testCall()
    // testCall1()
}



const testCall = () => {
    // bool ScriptEngine::runScript(const ccstd::string &path, Value *ret /* = nullptr */)
    A(getExportFromName('_ZN2se12ScriptEngine9runScriptERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPNS_5ValueE'), (args) => {
        LOGD(hexdump(args[0]))
        LOGD("---")
        LOGD(hexdump(args[1]))
        LOGD("---")
        LOGD(hexdump(args[2]))
        LOGD(`[+] testCall:${args[0]} ${args[1]} => ${new StdString(args[1].readPointer()).toString()}}`)
    })

    A(getExportFromName('_ZNK2se12ScriptEngine17isDebuggerEnabledEv'), (args) => { }, (ret) => {
        LOGD("called _ZNK2se12ScriptEngine17isDebuggerEnabledEv ret = " + ret)
        ret.replace(ptr(1))
    })

    // ccstd::string ScriptEngine::getCurrentStackTrace()
    A(getExportFromName('_ZN2se12ScriptEngine20getCurrentStackTraceEv'), (args) => {
        LOGD("Called _ZN2se12ScriptEngine20getCurrentStackTraceEv")
    }, (ret) => {
        LOGD("Called _ZN2se12ScriptEngine20getCurrentStackTraceEv ret = " + ret.readCString())
    })

    A(getExportFromName('_ZN2v86Script3RunENS_5LocalINS_7ContextEEE'), () => {
        LOGD('enter _ZN2v86Script3RunENS_5LocalINS_7ContextEEE')
    })

}

globalThis.HookevalString = HookevalString

declare global {
    var HookevalString: () => void
}