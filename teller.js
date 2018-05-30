// teller.js
const jsonStream = require("duplex-json-stream")
const net = require("net")
const sodium = require("sodium-native")
const fs = require("fs")

// Get array of arguments and slice unnecessary elms
const argv = process.argv.slice(2)
const customerId = argv[0]
const privateKey = argv[1]
let command = argv[2]

// Get last hashes for users if any are stored on disk
var lastHashes = {}
if (fs.existsSync("./tellerLog.json")) {
  lastHashes = require("./tellerLog.json")
}

// Adjust the command variable depending on arguments given
command = argv.length == 1 ? argv[0] : command

// Function to update a user's last transaction hash in file
const writeLastHash = (hash, customerId) => {
  lastHashes[customerId] = hash
  fs.writeFileSync(
    "./tellerLog.json",
    JSON.stringify(lastHashes, null, 2),
    "utf-8"
  )
}

// Signs a message with the user's secret key (provided as an argument)
const signMessage = message => {
  // Allocate a buffer for the signature
  let signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  // Get the hash of the user's last transactions and add to message
  // This is part of a mechanism to prevent replay attacks
  message.lastHash = lastHashes[message.customerId]
  // Sign the message
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(JSON.stringify(message)),
    Buffer.from(privateKey, "base64")
  )
  return signature.toString("base64")
}

// Create a teller
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
