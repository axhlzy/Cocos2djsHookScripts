import StdString from "./utils/std/std_string"

var soAddress: NativePointer = ptr(0)

const id = setInterval(() => {
    let md = Module.findBaseAddress("libcocos2djs.so")
    if (md != null) {
        soAddress = md
        console.log("soAddress: " + soAddress)
        todo()
        clearInterval(id)
    }
}, 1000)


const todo = () => {
    // cocos2d::extension::AssetsManagerEx::fileSuccess(std::string const&, std::string const&)
    // void AssetsManagerEx::fileSuccess(const std::string &customId, const std::string & /*storagePath*/) {
    Interceptor.attach(soAddress.add(0x760D98), {
        onEnter: function (args) {
            console.log("fileSuccess ", args[0])
            console.log(new StdString(args[1]).toString())
            console.log(new StdString(args[2]).toString())
        },
        onLeave: function (retval) {
        }
    })



}