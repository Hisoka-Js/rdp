// test4.js
console.log("[+] Script started");

setTimeout(function() {
    console.log("[+] All modules:");
    Process.enumerateModules().forEach(m => {
        console.log(`    ${m.name}`);
    });
}, 3000);
