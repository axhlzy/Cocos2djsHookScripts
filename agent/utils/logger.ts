const logL = console.log

export enum LogColor {
    WHITE = 0, RED = 1, YELLOW = 3,
    C31 = 31, C32 = 32, C33 = 33, C34 = 34, C35 = 35, C36 = 36,
    C41 = 41, C42 = 42, C43 = 43, C44 = 44, C45 = 45, C46 = 46,
    C90 = 90, C91 = 91, C92 = 92, C93 = 93, C94 = 94, C95 = 95, C96 = 96, C97 = 97,
    C100 = 100, C101 = 101, C102 = 102, C103 = 103, C104 = 104, C105 = 105, C106 = 106, C107 = 107
}

function callOnce<T extends Function>(func: T): T {
    let called = false
    return ((...args: any[]) => {
        if (!called) {
            called = true
            return func(...args)
        }
    }) as unknown as T
}

export const LOG = (str: any, type: LogColor = LogColor.WHITE): void => {
    switch (type) {
        case LogColor.WHITE: logL(str); break
        case LogColor.RED: console.error(str); break
        case LogColor.YELLOW: console.warn(str); break
        default: logL("\x1b[" + type + "m" + str + "\x1b[0m"); break
    }
}

export const LOGJSON = (obj: any, type: LogColor = LogColor.C36, lines: number = 1): void => LOG(JSON.stringify(obj, null, lines), type)

const colorEndDes: string = "\x1b[0m"
const colorStartDes = (color: LogColor): string => `\x1b[${color as number}m`

export const LOGW = (msg: any): void => LOG(msg, LogColor.YELLOW)
export const LOGE = (msg: any): void => LOG(msg, LogColor.RED)
export const LOGG = (msg: any): void => LOG(msg, LogColor.C32)
export const LOGD = (msg: any): void => LOG(msg, LogColor.C36)
export const LOGO = (msg: any): void => LOG(msg, LogColor.C33)
export const LOGP = (msg: any): void => LOG(msg, LogColor.C34)
export const LOGM = (msg: any): void => LOG(msg, LogColor.C92)
export const LOGH = (msg: any): void => LOG(msg, LogColor.C96)
export const LOGZ = (msg: any): void => LOG(msg, LogColor.C90)

export const printLogColors = (): void => {
    let str = "123456789"
    logL(`\n${getLine(16)}  listLogColors  ${getLine(16)}`)
    for (let i = 30; i <= 37; i++) {
        logL(`\t\t${colorStartDes(i)} C${i}\t${str} ${colorEndDes}`)
    }
    logL(getLine(50))
    for (let i = 40; i <= 47; i++) {
        logL(`\t\t${colorStartDes(i)} C${i}\t${str} ${colorEndDes}`)
    }
    logL(getLine(50))
    for (let i = 90; i <= 97; i++) {
        logL(`\t\t${colorStartDes(i)} C${i}\t${str} ${colorEndDes}`)
    }
    logL(getLine(50))
    for (let i = 100; i <= 107; i++) {
        logL(`\t\t${colorStartDes(i)} C${i}\t${str} ${colorEndDes}`)
    }
    logL(getLine(50))
}

let linesMap = new Map()
export const getLine = (length: number, fillStr: string = "-") => {
    if (length == 0) return ""
    let key = length + "|" + fillStr
    if (linesMap.get(key) != null) return linesMap.get(key)
    for (var index = 0, tmpRet = ""; index < length; index++) tmpRet += fillStr
    linesMap.set(key, tmpRet)
    return tmpRet
}

declare global {
    var LOG: (str: any, type?: LogColor) => void
    var LOGJSON: (obj: any, type?: LogColor, lines?: number) => void
    var LOGW: (msg: any) => void // LogColor.YELLOW
    var LOGE: (msg: any) => void // LogColor.RED
    var LOGD: (msg: any) => void // LogColor.C36
    var LOGG: (msg: any) => void // LogColor.C32
    var LOGO: (msg: any) => void // LogColor.C33
    var LOGP: (msg: any) => void // LogColor.C33
    var LOGH: (msg: any) => void // LogColor.C96
    var LOGM: (msg: any) => void // LogColor.C96
    var LOGZ: (msg: any) => void // LogColor.C90
    var callOnce: (func: Function) => Function
    var newLine: (lines?: number) => void
    var getLine: (length: number, fillStr?: string) => string
    var printLogColors: () => void
    var LogColor: any
}

globalThis.LOG = LOG
globalThis.LOGJSON = LOGJSON
globalThis.LOGW = LOGW
globalThis.LOGE = LOGE
globalThis.LOGG = LOGG
globalThis.LOGD = LOGD
globalThis.LOGO = LOGO
globalThis.LOGP = LOGP
globalThis.LOGH = LOGH
globalThis.LOGM = LOGM
globalThis.LOGZ = LOGZ
globalThis.getLine = getLine
globalThis.printLogColors = printLogColors
globalThis.newLine = (lines: number = 1) => LOG(getLine(lines, "\n"))
globalThis.callOnce = callOnce
globalThis.LogColor = LogColor