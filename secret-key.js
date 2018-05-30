var sodium = require("sodium-native")
var secretKey = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
sodium.randombytes_buf(secretKey)
console.log(secretKey.toString("base64"))
