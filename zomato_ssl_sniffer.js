//zomato-sniff.js
//frida -U -f com.application.zomato -l zomato-sniff.js --no-pause

var resolver = new ApiResolver('module');
var addr_SSL_read = resolver.enumerateMatches('exports:*!SSL_read')[0].address;
var addr_SSL_write = resolver.enumerateMatches('exports:*!SSL_write')[0].address;


Interceptor.attach(addr_SSL_read, {
    onEnter: function (args) {
        this.buf = args[1];
        this.num = args[2].toInt32();
    },

    onLeave: function (retval) {
        if (this.num>256) this.num=256;
        console.log('[*] SSL_read: app <- server')
        console.log(hexdump(this.buf, {length: this.num}));
    }
});


Interceptor.attach(addr_SSL_write, {
    onEnter: function (args) {
        const buf = args[1];
        const num = args[2].toInt32();

        console.log('[*] SSL_write: app -> server')
        if (num>256) num=256;
        console.log(hexdump(buf, {length: num}));
    }
});