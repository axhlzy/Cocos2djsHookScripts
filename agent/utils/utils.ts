import { json } from "node:stream/consumers"
import { soName } from "./cocos"

export function callFunction(value: number | NativePointer, ..._args: any[]): NativePointer {
    try {
        if (value == undefined) return ptr(0x0)
        for (let i = 1; i <= (arguments.length < 5 ? 5 : arguments.length) - 1; i++)
            arguments[i] = arguments[i] == undefined ? ptr(0x0) : ptr(String(arguments[i]))
        if (value instanceof NativePointer) {
            return new NativeFunction(value, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
                (arguments[1], arguments[2], arguments[3], arguments[4])
        }
        return new NativeFunction(Module.findBaseAddress(soName)!.add(value), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
            (arguments[1], arguments[2], arguments[3], arguments[4])
    } catch {
        return ptr(0)
    }
}

enum passValueKey {
    org = "org",
    src = "src",
    enter = "enter",
    leave = "leave",
    time = "time"
}

let map_attach_listener = new Map<ARGM, InvocationListener>()
type ARGM = NativePointer | number | any
type PassType = passValueKey | string
type OnEnterType = (args: InvocationArguments, ctx: CpuContext, passValue: Map<PassType, any>) => void
type OnExitType = (retval: InvocationReturnValue, ctx: CpuContext, passValue: Map<PassType, any>) => void

const attachNative = (mPtr: ARGM, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord: boolean = true): void => {
    if (typeof mPtr == "number") mPtr = ptr(mPtr)
    if (mPtr instanceof NativePointer && mPtr.isNull()) return
    var passValue = new Map()
    passValue.set(passValueKey.org, mPtr)
    passValue.set(passValueKey.src, mPtr)
    passValue.set(passValueKey.enter, mOnEnter)
    passValue.set(passValueKey.leave, mOnLeave)
    passValue.set(passValueKey.time, new Date())
    mPtr = checkPointer(mPtr)
    let Listener = Interceptor.attach(mPtr, {
        onEnter: function (args: InvocationArguments) {
            if (mOnEnter != undefined) mOnEnter(args, this.context, passValue)
        },
        onLeave: function (retval: InvocationReturnValue) {
            if (mOnLeave != undefined) mOnLeave(retval, this.context, passValue)
        }
    })
    // 记录已经被Attach的函数地址以及listner,默认添加listener记录 (只有填写false的时候不记录)
    if (needRecord) map_attach_listener.set(String(mPtr), Listener)
}

const nop = (mPtr: NativePointer | number) => {
    if (typeof mPtr == "number") mPtr = ptr(mPtr)
    if (mPtr instanceof NativePointer && mPtr.isNull()) return
    mPtr = Module.findBaseAddress(soName)!.add(mPtr)
    Interceptor.replace(mPtr, new NativeCallback(() => {
        LOGD(`called NopFunction ${mPtr}`)
    }, 'void', []))
}


Java.perform(() => {

    var Utils = Java.use("com.applovin.mediation.unity.Utils")
    Utils.retrieveSdkKey.overload().implementation = function () {
        let ret = this.retrieveSdkKey()
        console.log(ret)
        return ret
    }

    // var MaxRewardedAd = Java.use("com.applovin.mediation.ads.MaxRewardedAd")
    // MaxRewardedAd.$init.overload('java.lang.String', 'com.applovin.sdk.AppLovinSdk').implementation = function () {
    //     console.log("MaxRewardedAd init")
    //     return this.$init.apply(this, arguments)
    // }

    // var MaxRewardedInterstitialAd = Java.use("com.applovin.mediation.ads.MaxRewardedInterstitialAd")
    // MaxRewardedInterstitialAd.$init.overload('java.lang.String', 'com.applovin.sdk.AppLovinSdk').implementation = function () {
    //     console.log("MaxRewardedInterstitialAd init")
    //     return this.$init.apply(this, arguments)
    // }

    // var MaxInterstitialAd = Java.use("com.applovin.mediation.ads.MaxInterstitialAd")
    // MaxInterstitialAd.$init.overload('java.lang.String', 'com.applovin.sdk.AppLovinSdk').implementation = function () {
    //     console.log("MaxInterstitialAd init")
    //     return this.$init.apply(this, arguments)
    // }

    // var MaxAdView = Java.use("com.applovin.mediation.ads.MaxAdView")
    // MaxAdView.$init.overload('java.lang.String', 'com.applovin.sdk.AppLovinSdk').implementation = function () {
    //     console.log("MaxAdView init")
    //     return this.$init.apply(this, arguments)
    // }

    hookAllOverloads("com.applovin.mediation.ads.MaxAdView", "$init")
    hookAllOverloads("com.applovin.mediation.ads.MaxInterstitialAd", "$init")
    hookAllOverloads("com.applovin.mediation.ads.MaxRewardedInterstitialAd", "$init")
    hookAllOverloads("com.applovin.mediation.ads.MaxRewardedAd", "$init")
})

function hookAllOverloads(targetClass, targetMethod) {
    Java.perform(function () {
        var targetClassMethod = targetClass + '.' + targetMethod;
        var hook = Java.use(targetClass);
        var overloadCount = hook[targetMethod].overloads.length;
        console.log("watch" + targetClass + targetMethod);

        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function () {
                // 打印出参数类型 以及参数个数
                var types = this.argumentTypes;
                for (var j = 0; j < types.length; j++) {
                    console.log("arg" + j + " type:" + types[j]);
                }
                console.log("\n" + targetClassMethod + " args" + arguments.length + " with: " + JSON.stringify(arguments));
                var retval = this[targetMethod].apply(this, arguments);
                PrintStackTrace()
                return retval;
            }
        }
    });
}

var PrintStackTrace = () => console.log(GetStackTrace())

var GetStackTrace = () => Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())


globalThis.A = attachNative
globalThis.n = nop

declare global {
    var A: (mPtr: NativePointer | number, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord?: boolean) => void
    var n: (mPtr: NativePointer | number) => void
}