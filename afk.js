// test.js
console.log("[+] Frida script loaded");

setTimeout(function() {
    console.log("[+] Testing module enumeration:");
    Process.enumerateModules({
        onMatch: function(module) {
            if (module.name.includes("libil2cpp")) {
                console.log(`    Found: ${module.name} at ${module.base}`);
                console.log(`    Size: ${module.size}`);
            }
        },
        onComplete: function() {}
    });
}, 3000);
