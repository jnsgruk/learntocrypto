// teller.js
var jsonStream = require("duplex-json-stream")
var net = require("net")
const sodium = require("sodium-native")
const fs = require("fs")

const argv = process.argv.slice(2)

const customerId = argv[0]
const privateKey = argv[1]
let command = argv[2]

var lastHashes = {}
if (fs.existsSync("./tellerLog.json")) {
  lastHashes = require("./tellerLog.json")
}

command = argv.length == 1 ? argv[0] : command

const writeLastHash = (hash, customerId) => {
  lastHashes[customerId] = hash
  fs.writeFileSync(
    "./tellerLog.json",
    JSON.stringify(lastHashes, null, 2),
    "utf-8"
  )
}

const signMessage = message => {
  let signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  message.lastHash = lastHashes[message.customerId]
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(JSON.stringify(message)),
    new Buffer(privateKey, "base64")
  )
  return signature.toString("base64")
}

var client = jsonStream(net.connect(3876))

client.on("data", function(msg) {
  msg = JSON.parse(msg)
  console.log(msg)
  if (msg.hash) writeLastHash(msg.hash, msg.customerId)
})

let message,
  signature = null

switch (command) {
  case "balance":
    message = { cmd: "balance", customerId: customerId }
    signature = signMessage(message)
    client.end({ message, signature })
    break
  case "deposit":
    const amount = parseFloat(argv[3])
    message = { cmd: "deposit", amount: amount, customerId: customerId }
    signature = signMessage(message)
    client.end({ message, signature })
    break
  case "withdraw":
    const wdwAmount = parseFloat(argv[3])
    message = {
      cmd: "withdraw",
      amount: -wdwAmount,
      customerId: customerId,
    }
    signature = signMessage(message)
    client.end({ message, signature })
    break
  case "register":
    client.end({ message: { cmd: "register" } })
    break
  default:
    console.log("Valid commands are register, balance, withdraw, deposit")
}
