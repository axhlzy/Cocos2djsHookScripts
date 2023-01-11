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

globalThis.A = attachNative
globalThis.n = nop

declare global {
    var A: (mPtr: NativePointer | number, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord?: boolean) => void
    var n: (mPtr: NativePointer | number) => void
}