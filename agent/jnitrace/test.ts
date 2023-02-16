
import { JNIInterceptor } from "jnitrace-engine";
import { JNILibraryWatcher } from "jnitrace-engine";
import { JNINativeReturnValue } from "jnitrace-engine";
import { ConfigBuilder } from "jnitrace-engine";


// setImmediate(main)

function main() {

    // configure the jnitrace-engine to limit what libraries to traces
    const builder: ConfigBuilder = new ConfigBuilder();

    builder.libraries = ["libcocos2djs.so"]; // set a list of libraries to track
    builder.backtrace = "fuzzy"; // choose the backtracer type to use [accurate/fuzzy/none]
    // builder.includeExports = [ "Java_com_nativetest_MainActivity_stringFromJNI" ]; // provide a list of library exports to track
    builder.excludeExports = []; // provide a list of library exports to ignore
    builder.env = true; // set whether to trace the JNIEnv struct or ignore all of it
    builder.vm = false; // set whether to trace the JavaVM struct or ignore all of it

    const config = builder.build(); //initialise the config - this makes it available to the engine

    let loaderCallback = () => {
        JNILibraryWatcher.setCallback({
            onLoaded(path: string) {
                console.log("Library Loaded " + path);
                console.log("Currently Traced Libraries", JSON.stringify(config.libraries));
            }
        })
    }

    JNIInterceptor.attach("CallDoubleMethodV", {
        onLeave(retval: JNINativeReturnValue) {
            // Log the method params of the Java method the JNI API is calling.
            // this.javaMethod will only exist if a Java method has been called.
            console.log("Java Method Args", JSON.stringify(this.javaMethod!.params));
        }
    });


}
