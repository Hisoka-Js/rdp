const TARGET_KEY = "abcdef1234567890abcdef1234567890";
const KEY_LENGTH = TARGET_KEY.length;

console.log(`[+] Starting key tracing: ${TARGET_KEY}`);
console.log(`[+] Key length: ${KEY_LENGTH} bytes`);

function findKeyInMemory() {
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        console.log(`[+] Module found: ${module.name}`);
        console.log(`[+] Range: ${module.base} - ${module.base.add(module.size)}`);
        
        const results = Memory.scanSync(module.base, module.size, TARGET_KEY);
        
        if (results.length > 0) {
            console.log(`[+] Key found in ${results.length} locations:`);
            results.forEach((match, index) => {
                console.log(`    ${index + 1}. Address: ${match.address}`);
                
                const nearbyFunction = DebugSymbol.fromAddress(match.address);
                if (nearbyFunction) {
                    console.log(`       Nearby function: ${nearbyFunction.name}`);
                }
            });
        } else {
            console.log(`[-] Key not found directly in memory`);
        }
    } catch (e) {
        console.log(`[-] Module not loaded yet, retrying in 1 second...`);
        setTimeout(findKeyInMemory, 1000);
    }
}

function traceKeyUsage() {
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        Interceptor.attach(module.base, {
            onEnter: function(args) {
                for (let i = 0; i < 5; i++) {
                    try {
                        const param = args[i];
                        if (param) {
                            const str = param.readCString();
                            if (str && str.includes(TARGET_KEY)) {
                                console.log(`[!] Key found in parameter ${i}`);
                                console.log(`    Function: ${DebugSymbol.fromAddress(this.returnAddress)}`);
                                console.log(`    Value: ${str}`);
                            }
                            
                            const bytes = param.readByteArray(KEY_LENGTH);
                            if (bytes) {
                                const bytesStr = Array.from(bytes).map(b => 
                                    String.fromCharCode(b)).join('');
                                if (bytesStr === TARGET_KEY) {
                                    console.log(`[!] Key found as bytes in parameter ${i}`);
                                    console.log(`    Function: ${DebugSymbol.fromAddress(this.returnAddress)}`);
                                }
                            }
                        }
                    } catch (e) {}
                }
            }
        });
        
        console.log("[+] Function call tracing activated");
        traceSpecificFunctions();
        findKeyInStrings();
        
    } catch (e) {
        console.log(`[-] Module not loaded yet, waiting...`);
        setTimeout(traceKeyUsage, 1000);
    }
}

function traceSpecificFunctions() {
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        const functionsToTrace = [
            "strcmp",
            "memcmp",
            "strstr",
            "memcpy",
            "strcpy",
            "strncmp",
            "memmem"
        ];
        
        functionsToTrace.forEach(funcName => {
            try {
                const funcPtr = Module.findExportByName(null, funcName);
                if (funcPtr) {
                    Interceptor.attach(funcPtr, {
                        onEnter: function(args) {
                            for (let i = 0; i < 2; i++) {
                                try {
                                    const str = args[i].readCString();
                                    if (str && str.includes(TARGET_KEY)) {
                                        console.log(`[!!!] Key found in ${funcName} (parameter ${i})`);
                                        console.log(`    Backtrace: ${Thread.backtrace(this.context, Backtracer.ACCURATE)
                                            .map(DebugSymbol.fromAddress).join('\n    ')}`);
                                    }
                                } catch (e) {}
                            }
                        }
                    });
                    console.log(`[+] Tracing function: ${funcName}`);
                }
            } catch (e) {
                console.log(`[-] Failed to trace ${funcName}: ${e}`);
            }
        });
    } catch (e) {
        setTimeout(traceSpecificFunctions, 1000);
    }
}

function findKeyInStrings() {
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        Memory.scan(module.base, module.size, TARGET_KEY, {
            onMatch: function(address, size) {
                console.log(`[+] Key found as string at: ${address}`);
                
                const containingFunction = DebugSymbol.fromAddress(address);
                if (containingFunction) {
                    console.log(`    Inside function: ${containingFunction.name}`);
                }
                
                console.log(`    Searching for references...`);
                
                Memory.scan(module.base, module.size, address.toString(), {
                    onMatch: function(refAddress, refSize) {
                        console.log(`    Reference at: ${refAddress}`);
                        const refFunction = DebugSymbol.fromAddress(refAddress);
                        if (refFunction) {
                            console.log(`    In function: ${refFunction.name}`);
                        }
                    },
                    onComplete: function() {}
                });
            },
            onComplete: function() {
                console.log("[+] String search completed");
            }
        });
    } catch (e) {
        setTimeout(findKeyInStrings, 1000);
    }
}

function main() {
    console.log("=".repeat(50));
    console.log("Starting key tracing in libil2cpp.so");
    console.log("=".repeat(50));
    
    // بدء المراقبة بعد تحميل المكتبة
    findKeyInMemory();
    traceKeyUsage();
}

// انتظار تحميل التطبيق
setTimeout(main, 3000);
