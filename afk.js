const TARGET_KEY = "abcdef1234567890abcdef1234567890";
const KEY_LENGTH = TARGET_KEY.length;

console.log(`[+] Starting key tracing: ${TARGET_KEY}`);
console.log(`[+] Key length: ${KEY_LENGTH} bytes`);

function waitForModule(moduleName, callback) {
    const interval = setInterval(function() {
        try {
            const module = Process.getModuleByName(moduleName);
            if (module) {
                clearInterval(interval);
                console.log(`[+] Module ${moduleName} loaded at: ${module.base}`);
                callback(module);
            }
        } catch (e) {
            // Module not loaded yet
        }
    }, 1000);
}

function startTracing(module) {
    console.log("=".repeat(50));
    console.log("Starting key tracing");
    console.log("=".repeat(50));
    
    // البحث عن المفتاح
    const results = Memory.scanSync(module.base, module.size, TARGET_KEY);
    
    if (results.length > 0) {
        console.log(`[+] Key found in ${results.length} locations:`);
        results.forEach((match, index) => {
            console.log(`    ${index + 1}. Address: ${match.address}`);
        });
    }
    
    // تتبع الدوال
    Interceptor.attach(module.base, {
        onEnter: function(args) {
            for (let i = 0; i < 5; i++) {
                try {
                    const param = args[i];
                    if (param) {
                        const str = param.readCString();
                        if (str && str.includes(TARGET_KEY)) {
                            console.log(`[!] Key used at: ${DebugSymbol.fromAddress(this.returnAddress)}`);
                        }
                    }
                } catch (e) {}
            }
        }
    });
    
    console.log("[+] Tracing active");
}

// انتظار تحميل المكتبة
waitForModule("libil2cpp.so", startTracing);
