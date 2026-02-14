const TARGET_KEY = "abcdef1234567890abcdef1234567890";
const TARGET_CLASS = "UDPSession";
const TARGET_NAMESPACE = "GCommon";

console.log(`[+] Starting targeted tracing for ${TARGET_NAMESPACE}.${TARGET_CLASS}`);
console.log(`[+] Looking for key: ${TARGET_KEY}`);

function waitForModule() {
    return new Promise(resolve => {
        const check = setInterval(() => {
            try {
                const module = Process.getModuleByName("libil2cpp.so");
                if (module) {
                    clearInterval(check);
                    console.log(`[+] libil2cpp.so loaded at: ${module.base}`);
                    resolve(module);
                }
            } catch (e) {}
        }, 1000);
    });
}

function findClassMethods(module) {
    return new Promise(resolve => {
        console.log(`\n[+] Searching for ${TARGET_CLASS} methods...`);
        
        // البحث عن توقيع الكلاس في الذاكرة
        const className = `${TARGET_NAMESPACE}.${TARGET_CLASS}`;
        const classNamePattern = className.split('').map(c => c.charCodeAt(0)).join(' ');
        
        const methods = [];
        
        Memory.scan(module.base, module.size, classNamePattern, {
            onMatch: function(address) {
                console.log(`[+] Found class reference at: ${address}`);
                
                // البحث عن الدوال القريبة
                for (let offset = -0x100; offset < 0x100; offset += 4) {
                    try {
                        const possibleMethod = address.add(offset);
                        const code = possibleMethod.readPointer();
                        
                        // التحقق إذا كان هذا مؤشر لدالة
                        if (code >= module.base && code < module.base.add(module.size)) {
                            methods.push({
                                address: possibleMethod,
                                code: code
                            });
                        }
                    } catch (e) {}
                }
            },
            onComplete: function() {
                console.log(`[+] Found ${methods.length} possible methods`);
                resolve(methods);
            }
        });
    });
}

function traceUDPSession() {
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        // الدوال المهمة في UDPSession
        const targetMethods = [
            "UpdateSessionKey",
            "get_DecTempBuffer",
            "get_EncTempBuffer",
            "get_DecBuffer",
            "get_EncBuffer",
            "OnRecvDataThread",
            "OnSendDataThread",
            "Send"
        ];
        
        console.log("\n[+] Tracing UDPSession methods:");
        
        // البحث عن كل دالة وتتبعها
        targetMethods.forEach(methodName => {
            try {
                // البحث عن الدالة في الذاكرة
                const pattern = methodName.split('').map(c => c.charCodeAt(0)).join(' ');
                
                Memory.scan(module.base, module.size, pattern, {
                    onMatch: function(address) {
                        console.log(`    Found ${methodName} at: ${address}`);
                        
                        // تتبع الدالة
                        Interceptor.attach(address, {
                            onEnter: function(args) {
                                // this هو الكائن الحالي (UDPSession)
                                const session = args[0];
                                
                                console.log(`\n[!!!] ${methodName} called`);
                                console.log(`    Session address: ${session}`);
                                
                                // فحص الـ fields المهمة
                                try {
                                    // m_SessionKey في offset 0xA0
                                    const sessionKeyPtr = session.add(0xA0).readPointer();
                                    if (sessionKeyPtr) {
                                        const sessionKey = sessionKeyPtr.readCString();
                                        if (sessionKey) {
                                            console.log(`    SessionKey: ${sessionKey}`);
                                            
                                            // مقارنة مع المفتاح المستهدف
                                            if (sessionKey === TARGET_KEY) {
                                                console.log(`[!!!] TARGET KEY FOUND IN SESSION!`);
                                                console.log(`    Backtrace: ${Thread.backtrace(this.context, Backtracer.ACCURATE)
                                                    .map(DebugSymbol.fromAddress).join('\n    ')}`);
                                            }
                                        }
                                    }
                                } catch (e) {}
                                
                                // فحص المعاملات الإضافية
                                if (methodName === "UpdateSessionKey" && args.length > 1) {
                                    try {
                                        const key = args[1].readCString();
                                        console.log(`    New SessionKey: ${key}`);
                                        
                                        if (key === TARGET_KEY) {
                                            console.log(`[!!!] TARGET KEY BEING SET!`);
                                        }
                                    } catch (e) {}
                                }
                                
                                if (methodName === "Send" && args.length > 2) {
                                    try {
                                        const cmd = args[1].toInt32();
                                        const data = args[2];
                                        const size = args[3].toInt32();
                                        
                                        console.log(`    Send - CMD: ${cmd}, Size: ${size}`);
                                        
                                        // فحص البيانات المرسلة للبحث عن المفتاح
                                        if (size > 0 && size < 1024) {
                                            const sentData = data.readByteArray(size);
                                            if (sentData) {
                                                const dataStr = Array.from(sentData).map(b => 
                                                    String.fromCharCode(b)).join('');
                                                if (dataStr.includes(TARGET_KEY)) {
                                                    console.log(`[!!!] KEY FOUND IN SENT DATA!`);
                                                }
                                            }
                                        }
                                    } catch (e) {}
                                }
                            },
                            
                            onLeave: function(retval) {
                                if (methodName === "get_DecTempBuffer" || methodName === "get_EncTempBuffer") {
                                    try {
                                        const buffer = retval;
                                        if (buffer) {
                                            console.log(`    Buffer returned: ${buffer}`);
                                            
                                            // قراءة محتوى البافر
                                            const data = buffer.readByteArray(32);
                                            if (data) {
                                                const dataStr = Array.from(data).map(b => 
                                                    String.fromCharCode(b)).join('');
                                                if (dataStr.includes(TARGET_KEY.substring(0, 8))) {
                                                    console.log(`[!!!] KEY FOUND IN BUFFER!`);
                                                }
                                            }
                                        }
                                    } catch (e) {}
                                }
                            }
                        });
                    },
                    onComplete: function() {}
                });
            } catch (e) {
                console.log(`    Error tracing ${methodName}: ${e}`);
            }
        });
        
    } catch (e) {
        console.log(`[-] Error: ${e}`);
    }
}

function traceTeaBuffers() {
    console.log("\n[+] Tracing TEA buffers...");
    
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        // البحث عن TeaDecTempBuffer و TeaEncTempBuffer
        const teaClasses = ["TeaDecTempBuffer", "TeaEncTempBuffer"];
        
        teaClasses.forEach(teaClass => {
            const pattern = teaClass.split('').map(c => c.charCodeAt(0)).join(' ');
            
            Memory.scan(module.base, module.size, pattern, {
                onMatch: function(address) {
                    console.log(`[+] Found ${teaClass} at: ${address}`);
                    
                    // تتبع استخدام البافر
                    Interceptor.attach(address, {
                        onEnter: function(args) {
                            const buffer = args[0];
                            console.log(`\n[!!!] ${teaClass} accessed`);
                            
                            // فحص محتوى البافر
                            try {
                                const data = buffer.readByteArray(64);
                                if (data) {
                                    const dataStr = Array.from(data).map(b => 
                                        String.fromCharCode(b)).join('');
                                    if (dataStr.includes(TARGET_KEY)) {
                                        console.log(`[!!!] KEY FOUND IN ${teaClass}!`);
                                        console.log(`    Backtrace: ${Thread.backtrace(this.context, Backtracer.ACCURATE)
                                            .map(DebugSymbol.fromAddress).join('\n    ')}`);
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                },
                onComplete: function() {}
            });
        });
        
    } catch (e) {}
}

function tracePacketProcessing() {
    console.log("\n[+] Tracing packet processing...");
    
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        // تتبع معالجة الباكتات
        const packetMethods = [
            "OnRecvDataThread",
            "OnSendDataThread",
            "GetUDPPackets",
            "Resend"
        ];
        
        packetMethods.forEach(method => {
            const pattern = method.split('').map(c => c.charCodeAt(0)).join(' ');
            
            Memory.scan(module.base, module.size, pattern, {
                onMatch: function(address) {
                    Interceptor.attach(address, {
                        onEnter: function(args) {
                            console.log(`\n[!!!] Packet method: ${method} called`);
                            
                            // فحص الباكتات
                            if (method === "GetUDPPackets" && args.length > 1) {
                                try {
                                    const outPackets = args[1];
                                    console.log(`    OutPackets queue: ${outPackets}`);
                                } catch (e) {}
                            }
                            
                            if (method === "Resend" && args.length > 1) {
                                try {
                                    const packet = args[1];
                                    console.log(`    Resending packet: ${packet}`);
                                } catch (e) {}
                            }
                        }
                    });
                },
                onComplete: function() {}
            });
        });
        
    } catch (e) {}
}

function monitorSessionKey() {
    console.log("\n[+] Monitoring SessionKey changes...");
    
    try {
        const module = Process.getModuleByName("libil2cpp.so");
        
        // البحث عن جميع كائنات UDPSession في الذاكرة
        Memory.scan(module.base, module.size, "UDPSession".split('').map(c => c.charCodeAt(0)).join(' '), {
            onMatch: function(address) {
                // التحقق من أن هذا هو الكلاس الصحيح
                setTimeout(function() {
                    try {
                        // محاولة قراءة m_SessionKey من offset 0xA0
                        const possibleSession = address.sub(0x10); // تقدير عنوان الكائن
                        const sessionKeyPtr = possibleSession.add(0xA0).readPointer();
                        
                        if (sessionKeyPtr) {
                            const sessionKey = sessionKeyPtr.readCString();
                            if (sessionKey && sessionKey.length > 10) {
                                console.log(`[+] Found UDPSession at: ${possibleSession}`);
                                console.log(`    SessionKey: ${sessionKey}`);
                                
                                // مراقبة التغييرات في SessionKey
                                MemoryAccessMonitor.enable({
                                    base: possibleSession.add(0xA0),
                                    size: Process.pointerSize
                                }, {
                                    onAccess: function(details) {
                                        console.log(`\n[!!!] SessionKey modified!`);
                                        console.log(`    From: ${DebugSymbol.fromAddress(details.from)}`);
                                        
                                        // قراءة القيمة الجديدة
                                        try {
                                            const newKeyPtr = possibleSession.add(0xA0).readPointer();
                                            const newKey = newKeyPtr.readCString();
                                            console.log(`    New SessionKey: ${newKey}`);
                                            
                                            if (newKey === TARGET_KEY) {
                                                console.log(`[!!!] TARGET KEY SET IN SESSION!`);
                                            }
                                        } catch (e) {}
                                    }
                                });
                            }
                        }
                    } catch (e) {}
                }, 100);
            },
            onComplete: function() {}
        });
        
    } catch (e) {}
}

async function main() {
    console.log("=".repeat(60));
    console.log("UDPSession Key Tracer");
    console.log("=".repeat(60));
    
    try {
        const module = await waitForModule();
        
        // تشغيل جميع أدوات التتبع
        traceUDPSession();
        traceTeaBuffers();
        tracePacketProcessing();
        monitorSessionKey();
        
        console.log("\n[✓] All UDPSession tracers activated!");
        console.log("[!] Use the app normally to trigger key access");
        console.log("[!] Focus on: UpdateSessionKey, Tea buffers, and packet processing");
        
    } catch (e) {
        console.log(`[-] Error: ${e}`);
    }
}

setTimeout(main, 2000);
