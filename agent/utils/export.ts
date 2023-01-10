import { formartClass as FM } from './formart'
import { callFunction } from './utils'

const p_size = Process.pointerSize

declare global {
    var protect: (mPtr: NativePointer) => void
    var watch: (mPtr: NativePointer, length?: number) => void
    var watchDisabled: () => void
    var patchTest: (mPtr: NativePointer, size?: number) => void
    var findInMemory: (typeStr: "Dex" | "Dex1" | "PNG" | "global-metadata.dat" | string, scanSync?: boolean) => void
    var fridaInfo: () => void
    var listThreads: (maxCountThreads?: number) => void

    var listModules: (filterName?: string) => void
    var listModule: (moduleName: string, printItems?: number) => void
    /**
     * findExport 侧重点在定位一些我们只知道函数名不知道他在那个模块里面（用于定位导出函数）
     * 故exportName作为第一个参数，第二个参数用作筛选
     */
    var findExport: (exportName: string, moduleName?: string, callback?: (exp: ModuleExportDetails) => void) => void
    /**
     * findImport 侧重点在像IDA一样方便的查看指定Module的导入函数
     * 故ModuleName作为第一个参数，第二个参数用作筛选
     */
    var findImport: (moduleName: string, importName?: string) => void

    /**
     * Stalker Trace Event (单独关键点追踪)
     */
    var StalkerTraceEvent: (mPtr: NativePointer, range: NativePointer[] | undefined) => void
    /**
     * Stalker Trace Path (配合IDA标注程序执行路线)
     */
    var StalkerTracePath: (mPtr: NativePointer, range: NativePointer[] | undefined) => void

    var cmdouleTest: () => void
    var sqliteTest: () => void

    var checkPointer: (mPtr: NativePointer) => NativePointer
}

globalThis.protect = (mPtr: NativePointer, size: number = 0x1000, protection: PageProtection = "rwx") => {
    mPtr = mPtr.shr(3 * 4).shl(3 * 4)
    Memory.protect(mPtr, size, protection)
}

globalThis.watch = (mPtr: NativePointer, length: number = 0x10) => {

    class MenRange implements MemoryAccessRange {
        base: NativePointer
        size: number
        constructor(base: NativePointer, size: number) {
            this.base = base
            this.size = size
        }
    }

    class MemoryDetails implements MemoryAccessDetails {
        operation: MemoryOperation      // operation: 触发这次访问的操作类型, 仅限于 read, write, execute
        from: NativePointer             // from: NativePointer 类型的触发这次访问的指令的地址
        address: NativePointer          // address: NativePointer 类型的被访问的地址
        rangeIndex: number              // rangeIndex: 被访问的内存范围的索引
        pageIndex: number               // pageIndex: 被访问的页的索引
        pagesCompleted: number          // pagesCompleted: 到目前为止已访问(并且不再受监控)的内存页总数
        pagesTotal: number              // pagesTotal: 被访问的内存范围的总页数
        private mdFrom: Module
        private mdAddress: Module

        constructor(detail: MemoryAccessDetails) {
            this.operation = detail.operation
            this.from = detail.from
            this.address = detail.address
            this.rangeIndex = detail.rangeIndex
            this.pageIndex = detail.pageIndex
            this.pagesCompleted = detail.pagesCompleted
            this.pagesTotal = detail.pagesTotal
            this.mdAddress = Process.findModuleByAddress(this.address)!
            this.mdFrom = Process.findModuleByAddress(this.from)!
        }

        public tostring(): string {
            return `
operation:\t\t${this.operation}
from:\t\t\t${this.from} { ${this.from.sub(this.mdFrom.base)} @ ${this.mdFrom.name} }
address:\t\t${this.address} { ${this.address.sub(this.mdAddress.base)} @ ${this.mdAddress.name} }
rangeIndex:\t\t${this.rangeIndex}
pageIndex:\t\t${this.pageIndex}
pagesCompleted:\t\t${this.pagesCompleted}
pagesTotal:\t\t${this.pagesTotal}`
        }
    }

    // 监控一个或多个内存范围的访问情况, 并且在每个内存页第一次访问时触发回调函数 (onAccess)
    MemoryAccessMonitor.enable(new MenRange(mPtr, length), {
        // tips：如果同时对一个地址attach和watch则运行到该点时会崩溃 使用watch时注意先detach掉这个点的hook
        onAccess: (access: MemoryAccessDetails) => LOGD(new MemoryDetails(access).tostring())
    })
}

globalThis.watchDisabled = () => MemoryAccessMonitor.disable()

globalThis.sqliteTest = () => {
    var db, smt, row, name, bio;
    db = SqliteDatabase.open('/path/to/people.db');
    smt = db.prepare('SELECT name, bio FROM people WHERE age = ?');
    console.log('People whose age is 42:');
    smt.bindInteger(1, 42);
    while ((row = smt.step()) !== null) {
        name = row[0];
        bio = row[1];
        console.log('Name:', name);
        console.log('Bio:', bio);
    }
    smt.reset()
}

globalThis.patchTest = (mPtr: NativePointer, size: number = 1) => {
    Memory.patchCode(checkPointer(mPtr), Process.pageSize * size, (code: NativePointer) => {
        LOGD(code)
        let writer = new ArmWriter(code)
        writer.putLabel('start')
        writer.putNop()
        writer.putCallAddressWithArguments(Module.findExportByName("libil2cpp.so", "il2cpp_string_new")!, ['r10', 0x10])
        LOGD(writer.base + " " + writer.pc + " " + writer.offset + " " + writer.code)
        writer.putBlxReg('lr')
        writer.putBCondLabel("eq", 'start')
        writer.flush()
    })
}

globalThis.fridaInfo = () => {
    LOGD(`\n${getLine(40)}`)
    LOGD(`[*] Runtime : ${Script.runtime}`)
    LOGD(`[*] ThreadId : ${Process.getCurrentThreadId()}`)
    LOGD(`[*] Process.id : ${Process.id}`)
    LOGD(`[*] Process.arch : ${Process.arch}`)
    LOGD(`[*] Process.platform : ${Process.platform}`)
    LOGD(`[*] Process.pointerSize : ${Process.pointerSize}`)
    LOGD(`[*] Process.pageSize : ${Process.pageSize}`)
    LOGD(`[*] Process.codeSigningPolicy : ${Process.codeSigningPolicy}`)
    LOGD(`[*] Process.isDebuggerAttached : ${Process.isDebuggerAttached()}`)
    LOGD(`${getLine(40)}\n`)
}

let index: number
globalThis.listModules = (filterName: string = "") => {
    index = 0
    Process.enumerateModules().forEach((md: Module) => {
        if (md.name.includes(filterName)) printModule(md, true)
    })
}

globalThis.listModule = (moduleName: string, printItems: number = 5) => {

    let md = Process.getModuleByName(moduleName)
    if (md == null) {
        LOGE("NOT FOUND Module : " + moduleName)
        return
    }
    printModule(md, false)
    if (moduleName == "linker") return

    let protection: PageProtection = "" // all , r , w , x
    let range = md.enumerateRanges(protection)
    if (range.length > 0) {
        LOGO(`\t[-] enumerateRanges ( ${range.length} )`)
        range.sort((f: RangeDetails, s: RangeDetails) => f.base.compare(s.base))
            .forEach((item: RangeDetails) => {
                LOGZ(`\t\t${item.protection}\t${item.base} - ${item.base.add(item.size)} | ${FM.alignStr(String(ptr(item.size)), p_size + 8)} <- ${item.size}`)
            })
        LOG("")
    }

    let imp = md.enumerateImports()
    if (imp.length > 0) {
        LOGO(`\t[-] enumerateImports ( ${imp.length} )`)
        let arrTmpRecord: Array<string> = []
        imp.sort((a: ModuleImportDetails, b: ModuleImportDetails) => a.name.length - b.name.length)
            .slice(0, printItems).forEach((item: ModuleImportDetails) => {
                let address = FM.alignStr(String(item.address), p_size + 8)
                let importFromDes: string = "\t<---\t"
                try {
                    let tmd = Process.findModuleByAddress(item.address!)! //this can throw exception
                    let baseStr = ` @ ${tmd.base}`
                    if (item.type == "function" || item.type == "variable") // not undefined
                        importFromDes += `${tmd.name} ${arrTmpRecord.includes(tmd.name) ? FM.centerStr("...", baseStr.length) : baseStr}` //show base once
                    arrTmpRecord.push(tmd.name)
                } catch { importFromDes = "" }
                LOGZ(`\t\t${item.type}   ${address}  ${item.name} ${importFromDes}`)
            })
        if (imp.length > printItems) LOGZ("\t\t......\n")
    }

    let exp = md.enumerateExports()
    if (exp.length > 0) {
        LOGO(`\t[-] enumerateExports ( ${exp.length} )`)
        exp.sort((a: ModuleExportDetails, b: ModuleExportDetails) => a.name.length - b.name.length)
            .slice(0, printItems).forEach((item: ModuleExportDetails) => {
                let address = FM.alignStr(String(item.address), p_size + 8)
                LOGZ(`\t\t${item.type}   ${address}  ${item.name}`)
            })
        if (exp.length > printItems) LOGZ("\t\t......\n")
    }

    let sym = md.enumerateSymbols()
    if (sym.length > 0) {
        LOGO(`\t[-] enumerateSymbols ( ${sym.length} )`)
        sym.slice(0, printItems).forEach((item: ModuleSymbolDetails) => {
            LOGZ(`\t\t${item.isGlobal}  ${item.type}  ${item.name}  ${item.address}`)
        })
        if (sym.length > printItems) LOGZ("\t\t......\n")
    }
}

function printModule(md: Module, needIndex: boolean = false) {
    needIndex == true ? LOGD(`\n[${++index}]\t${md.name}`) : LOGD(`\n[*]\t${md.name}`)
    // 保留三位小数
    let fileLen = getFileLenth(md.path)
    let size = Math.round(md.size / 1024 / 1024 * 100) / 100
    let fileLenFormat = Math.round(fileLen / 1024 / 1024 * 100) / 100
    let extendFileLen = fileLen == 0 ? "" : `| FILE: ${fileLen} B ≈ ${fileLenFormat} MB `
    LOGZ(`\t${md.base} - ${(md.base.add(md.size))}  | MEM: ${ptr(md.size)} ( ${md.size} B = ${md.size / 1024} KB ≈ ${size} MB ) ${extendFileLen}`)
    LOGZ(`\t${md.path}\n`)
}

globalThis.findExport = (exportName: string, moduleName: string | undefined, callback?: (exp: ModuleExportDetails) => void) => {
    // 未填写回调函数就直接用默认回调函数来展示导出函数的详细信息
    if (callback == undefined) callback = showDetails
    if (moduleName == undefined) {
        // 遍历所有Module的导出函数
        Process.enumerateModules().forEach((md: Module) => {
            md.enumerateExports().forEach((exp: ModuleExportDetails) => {
                if (exp.name.indexOf(exportName) != -1) callback!(exp)
            })
        })
    } else {
        // 遍历指定Module下的导出函数
        let md: Module | null = Process.findModuleByName(moduleName)
        if (md == null) throw new Error("NOT FOUND Module : " + moduleName)
        md.enumerateExports().forEach((exp: ModuleExportDetails) => {
            if (exp.name.indexOf(exportName) != -1) callback!(exp)
        })
    }
    if (callback == showDetails) newLine()

    function showDetails(exp: ModuleExportDetails) {
        try {
            let md: Module = Process.findModuleByAddress(exp.address)!
            if (md == null) {
                // Process 找不到和linker相关的导出函数，这里单独处理一下 { exp: findExport("dlopen") }
                let mdt = Process.findModuleByName("linker")!
                mdt.enumerateExports().forEach((linkerExp: ModuleExportDetails) => {
                    if (linkerExp.address.equals(exp.address) && linkerExp.name == exp.name) md = mdt
                })
            }
            let rg: RangeDetails = Process.findRangeByAddress(exp.address)!
            LOGD(`\n[*] ${exp.type} -> address: ${exp.address} ( ${exp.address.sub(md.base)} ) | name: ${exp.name}`)
            LOGZ(`\t[-] base: ${md.base} | size: 0x${md.size.toString(16).padEnd(p_size * 2, " ")} <- module:  ${md.name}`)
            LOGZ(`\t[-] base: ${rg.base} | size: 0x${rg.size.toString(16).padEnd(p_size * 2, " ")} <- range:   ${rg.protection}`)
        } catch (error) {
            if (Process.findModuleByAddress(exp.address) == null) LOGE("Module not found")
            if (Process.findRangeByAddress(exp.address) == null) LOGE("Range not found")
            LOGD(JSON.stringify(exp))
        }
    }
}

globalThis.findImport = (moduleName: string = "libc.so", importName: string = "") => {
    let md = Process.findModuleByName(moduleName)
    if (md == null) {
        LOGE("NOT FOUND Module : " + moduleName)
        return
    }
    md.enumerateImports().forEach((imp: ModuleImportDetails) => {
        if (!imp.name.includes(importName)) return
        let subAddr = (imp == undefined || imp!.address == null) ? "" : ` ( ${imp!.address!.sub(Process.findModuleByAddress(imp!.address)!.base)} )`
        LOGD(`\n[*] ${imp.type} -> address: ${imp.address}${subAddr}  | name: ${imp.name}`)
        let impMdBase = Process.findModuleByName(imp!.module!)?.base
        LOGZ(`\t${imp.module == undefined ? "" : (imp.module + " ( " + impMdBase + " ) ")} \t ${imp.slot == undefined ? "" : imp.slot}`)
    })
    LOG("")
}

const getFileLenth = (filePath: string): number => {
    let file = callFunction(Module.findExportByName("libc.so", "fopen")!, Memory.allocUtf8String(filePath), Memory.allocUtf8String("rwx"))
    if (file.isNull()) return 0
    callFunction(Module.findExportByName("libc.so", "fseek")!, file, 0, 2)
    let len = callFunction(Module.findExportByName("libc.so", "ftell")!, file).toInt32()
    callFunction(Module.findExportByName("libc.so", "fclose")!, file)
    return len
}

globalThis.StalkerTraceEvent = (mPtr: NativePointer, range: NativePointer[] | undefined) => {
    let src_mPtr = mPtr
    mPtr = checkPointer(mPtr)
    if (mPtr == undefined || mPtr.isNull()) return
    const moduleG: Module | null = Process.findModuleByAddress(mPtr)
    if (moduleG == null) {
        LOGE(`Module not found { from ${mPtr}}`)
        return
    }
    if (range != undefined && range.length > 0) {
        for (let i = 0; i < range.length; i++) {
            range[i] = checkPointer(range[i])
        }
    }
    A(mPtr, (args, ctx, passValue) => {
        LOG("")
        passValue.set("len", FM.printTitileA(`Enter ---> arg0:${args[0]}  arg1:${args[1]}  arg2:${args[2]}  arg3:${args[3]} | ${Process.getCurrentThreadId()}`, LogColor.YELLOW))
        stalkerEnter(Process.getCurrentThreadId())
    }, (ret, ctx, passValue) => {
        LOGW(`${getLine(20)}\n Exit ---> ret : ${ret}\n${getLine(passValue.get("len"))}`)
        stalkerExit(Process.getCurrentThreadId())
    })
    LOGD(`Stalker Attached : ${mPtr} ( ${ptr(src_mPtr as unknown as number)} ) from ${moduleG.name} | ${Process.getCurrentThreadId()}`)

    function stalkerEnter(tid: ThreadId) {
        Stalker.follow(tid, {
            events: {
                call: true,
                ret: false,
                exec: false,
                block: false,
                compile: false
            },
            onReceive: function (events) {
                let msg: StalkerCallEventFull[] = Stalker.parse(events, {
                    annotate: true,     // 标注事件类型
                    stringify: false    // NativePointer 换为字符串
                }) as StalkerCallEventFull[]

                msg.forEach((event: StalkerCallEventFull) => {
                    let md1 = Process.findModuleByAddress(event[1] as NativePointer)
                    let md2 = Process.findModuleByAddress(event[2] as NativePointer)
                    LOGD(`${event[0]} Times:${event[3]} ${event[1]}@${md1?.name} ${event[2]}@${md2?.name} `)
                })
            }
        })
    }

    function stalkerExit(tid: ThreadId) {
        Stalker.unfollow()
        Stalker.garbageCollect()
    }
}

// exp: StalkerTracePath(0x4CA23C,[0x4CA23C,0x4CA308])
globalThis.StalkerTracePath = (mPtr: NativePointer, range: NativePointer[] | undefined) => {
    let src_mPtr = mPtr
    mPtr = checkPointer(mPtr)
    if (mPtr == undefined || mPtr.isNull()) return
    const moduleG: Module | null = Process.findModuleByAddress(mPtr)
    if (moduleG == null) {
        LOGE(`Module not found { from ${mPtr}}`)
        return
    }
    if (range != undefined && range.length > 0) {
        for (let i = 0; i < range.length; i++) {
            range[i] = checkPointer(range[i])
        }
    }
    A(mPtr, (args, ctx, passValue) => {
        LOG("")
        passValue.set("len", FM.printTitileA(`Enter ---> arg0:${args[0]}  arg1:${args[1]}  arg2:${args[2]}  arg3:${args[3]} | ${Process.getCurrentThreadId()}`, LogColor.YELLOW))
        stalkerEnter(Process.getCurrentThreadId())
    }, (ret, ctx, passValue) => {
        LOGW(`${getLine(20)}\n Exit ---> ret : ${ret}\n${getLine(passValue.get("len"))}`)
        stalkerExit(Process.getCurrentThreadId())
    })
    LOGD(`Stalker Attached : ${mPtr} ( ${ptr(src_mPtr as unknown as number)} ) from ${moduleG.name} | ${Process.getCurrentThreadId()}`)

    function stalkerEnter(tid: ThreadId) {
        let moduleMap = new ModuleMap((module) => {
            if (module.base.equals(moduleG!.base)) return true
            Stalker.exclude(module)
            return false
        })

        Stalker.follow(tid, {
            transform: (iterator: any | StalkerArmIterator | StalkerThumbIterator | StalkerArm64Iterator) => {
                let instruction = iterator.next()
                let isModuleCode = moduleMap.has(instruction.address)
                let subAddress = ptr(instruction.address)
                if (range != undefined) {
                    if (subAddress > range[0] && range[1] > subAddress)
                        LOGD(`[*] ${instruction.address} ( ${subAddress.sub(moduleG!.base)} ) ---> ${instruction.mnemonic} ${instruction.opStr}`)
                } else if (isModuleCode) {
                    LOGD(`[*] ${instruction.address} ( ${subAddress.sub(moduleG!.base)} ) ---> ${instruction.mnemonic} ${instruction.opStr}`)
                }
                do {
                    iterator.keep()
                } while (iterator.next() !== null)
            }
        })
    }

    function stalkerExit(tid: ThreadId) {
        Stalker.unfollow()
        Stalker.garbageCollect()
        LOGE("Stalker Exit : " + Process.getCurrentThreadId())
    }
}

globalThis.cmdouleTest = () => {
    var source =
        "#include <stdio.h>" +
        "void functionFromCModule(){" +
        "   printf(\"Print from CModule\n\");" +
        "}";
    var cModule = new CModule(source);
    console.log(JSON.stringify(cModule));
    var ptrFunctionFromCModule = cModule['functionFromCModule'];
    var functionFromCModule = new NativeFunction(ptrFunctionFromCModule, 'void', []);
    functionFromCModule();
}

globalThis.checkPointer = (mPtr: NativePointer) => {
    return ptr(mPtr as unknown as number)
    // if (mPtr == undefined || mPtr.isNull())
    //     throw new Error("mPtr is null")
    // let md = Process.findModuleByAddress(mPtr)
    // if (md == null) return mPtr
    // else return md.base.add(mPtr)
}