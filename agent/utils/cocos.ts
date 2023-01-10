export const soName = "libcocos2djs.so"
export var soAddr = ptr(0)

const MAX_SHOW_TIME: number = 10

setImmediate(() => hook_dlopen())

function hook_dlopen(log: boolean = false) {
    const dlopen = Module.findExportByName(null, "dlopen");
    const dlopen1 = Module.findExportByName(null, "android_dlopen_ext");
    if (log) LOGD("dlopen = " + dlopen + "\tandroid_dlopen_ext = " + dlopen1)

    if (dlopen != null) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                let l_soName = args[0].readCString()!
                if (log) LOGD(l_soName)
                if (l_soName.indexOf(soName) != -1) {
                    this.hook = true
                }
            },
            onLeave: function (retval) {
                if (this.hook) {
                    if (log) LOGW("\nLoaded " + soName + " add break points")
                    soAddr = Module.findBaseAddress(soName)!
                    todo()
                }
            }
        })
    }

    if (dlopen1 != null) {
        Interceptor.attach(dlopen1, {
            onEnter: function (args) {
                let l_soName = args[0].readCString()!
                if (log) LOGD(l_soName)
                if (l_soName.indexOf(soName) != -1) {
                    this.hook = true
                }
            },
            onLeave: function (retval) {
                if (this.hook) {
                    if (log) LOGW("\nLoaded " + soName + " add break points")
                    soAddr = Module.findBaseAddress(soName)!
                    todo()
                }
            }
        })
    }
}

function todo() {
    // todo
}

export const getExportFromName = (name: string) => {
    if (name == undefined) throw new Error("partOfExpName is undefined")
    return Process.findModuleByName(soName)!
        .enumerateExports()
        .filter((e) => e.name.includes(name))[0].address
}

let mapCache = new Map<string, number>()
export const HookFunctions = (partOfExpName: string) => {
    if (partOfExpName == undefined) throw new Error("partOfExpName is undefined")
    iteratorExpFunctions(partOfExpName, (exp: ModuleExportDetails) => {
        try {
            A(exp.address, () => {
                if (mapCache.get(exp.name) == undefined) {
                    mapCache.set(exp.name, 1)
                } else {
                    mapCache.set(exp.name, mapCache.get(exp.name)! + 1)
                }
                if (mapCache.get(exp.name)! < MAX_SHOW_TIME) LOGD(`Called -> ${exp.name}`)
            })
        } catch (error) {
            LOGD(`Failed -> ${exp.name}`)
        }
    })
}

export const listFunctions = (partOfExpName: string) => {
    if (partOfExpName == undefined) throw new Error("partOfExpName is undefined")
    iteratorExpFunctions(partOfExpName, (item: ModuleExportDetails) => LOGD(`[*] ${item.address} -> ${item.name}`))
}

const iteratorExpFunctions = (name: string, callback: (item: ModuleExportDetails) => void, l_soName: string = soName) => {
    Process.findModuleByName(l_soName)!.enumerateExports().forEach((exp: ModuleExportDetails) => {
        if (exp.type == "function" && exp.name.toLowerCase().indexOf(name.toLowerCase()) != -1) callback(exp)
    })
}

globalThis.getExportFromName = getExportFromName
globalThis.HookFunctions = HookFunctions
globalThis.listFunctions = listFunctions

declare global {
    var getExportFromName: (name: string) => NativePointer
    var HookFunctions: (partOfExpName: string) => void
    var listFunctions: (partOfExpName: string) => void
}