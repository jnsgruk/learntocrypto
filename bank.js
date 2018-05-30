// bank.js
const jsonStream = require("duplex-json-stream")
const net = require("net")
const fs = require("fs")
const sodium = require("sodium-native")

const argv = process.argv.slice(2)
if (!argv[0]) {
  console.log("Please pass secret key as an argument!")
  process.exit(1)
}

const genesisHash = Buffer.alloc(32).toString("hex")
let privateKey, publicKey, encrypted_log
let log = []
const secretKey = new Buffer(argv[0], "base64")

// Function to traverse transaction log and return balance
const reduceLog = (balance, entry) => balance + entry.value.amount

// Hash input value and return string as hex
const hashToHex = value => {
  let output = Buffer.alloc(sodium.crypto_generichash_BYTES)
  const input = Buffer.from(value)
  sodium.crypto_generichash(output, input)
  return output.toString("hex")
}
// Append a new transaction with its hash and value
const appendToTransactionLog = entry => {
  let previousHash = log.length ? log[log.length - 1].hash : genesisHash
  let signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  let hash = hashToHex(previousHash + JSON.stringify(entry))
  sodium.crypto_sign_detached(signature, Buffer.from(hash), privateKey)
  log.push({
    value: entry,
    hash: hash,
    signature: signature.toString("base64"),
  })
  writeTransactionLog()
  return hash
}

const writeTransactionLog = () => {
  let transactionString = JSON.stringify(log, null, 2)

  let nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  let cipher = Buffer.alloc(
    transactionString.length + sodium.crypto_secretbox_MACBYTES
  )
  sodium.crypto_secretbox_easy(
    cipher,
    Buffer.from(transactionString),
    nonce,
    secretKey
  )

  let output = {
    cipherText: cipher.toString("base64"),
    nonce: nonce.toString("base64"),
  }
  fs.writeFileSync("./log.json", JSON.stringify(output, null, 2), "utf-8")
  fs.writeFileSync("./logDx.json", JSON.stringify(log, null, 2), "utf-8")
}

// Check the hash chain the log and exit if it's been messed with
const validateLogChain = log => {
  log.map((current, index, array) => {
    // First verify the hash is correct by re-generating and comparing
    let previousHash = index ? array[index - 1].hash : genesisHash
    let hash = hashToHex(previousHash + JSON.stringify(current.value))
    return hash == current.hash ? true : process.exit(1)
    // Now hashes are correct, check that signature matches
    let signature = new Buffer(current.signature, "base64")
    let correctSignature = sodium.crypto_sign_verify_detached(
      signature,
      Buffer.from(current.hash),
      publicKey
    )
    return correctSignature ? true : process.exit(1)
  })
  console.log("Verified transaction log successfully!")
}

const checkCustomerExists = customerId => {
  const registerEvents = log.filter(entry => entry.value.cmd === "register")
  const customers = registerEvents.filter(
    event => event.value.customerId === customerId
  )
  return customers.length > 0
}

const getBalance = customerId => {
  const balanceEvents = log.filter(
    entry =>
      entry.value.cmd !== "register" && entry.value.customerId === customerId
  )
  return balanceEvents.reduce(reduceLog, 0)
}

const getKeypair = () => {
  let publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  let privateKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, privateKey)
  return { privateKey, publicKey }
}

if (fs.existsSync("./log.json")) {
  encrypted_log = require("./log.json")
  const cipher = new Buffer(encrypted_log.cipherText, "base64")
  const nonce = new Buffer(encrypted_log.nonce, "base64")

  let logString = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
  var bool = sodium.crypto_secretbox_open_easy(
    logString,
    cipher,
    nonce,
    secretKey
  )
  if (!bool) {
    console.log("Failed to decrypt log!")
    process.exit(1)
  } else {
    console.log("Log file decrypted successfully!")
    log = JSON.parse(logString.toString())
    validateLogChain(log)
  }
}

// Check if keys file exists, if it does load it. If not generate one
if (fs.existsSync("./keys.json")) {
  let keys = require("./keys.json")
  publicKey = new Buffer(keys.publicKey, "base64")
  privateKey = new Buffer(keys.privateKey, "base64")
} else {
  const { privateKey, publicKey } = getKeypair()
  fs.writeFileSync(
    "./keys.json",
    JSON.stringify(
      {
        publicKey: publicKey.toString("base64"),
        privateKey: privateKey.toString("base64"),
      },
      null,
      2
    ),
    "utf-8"
  )
}

const processCommand = (msg, socket) => {
  let hash = null
  switch (msg.cmd) {
    case "balance":
      if (checkCustomerExists(msg.customerId)) {
        socket.end(
          JSON.stringify({
            cmd: "balance",
            balance: getBalance(msg.customerId),
          })
        )
        break
      }
      socket.end(
        JSON.stringify({ cmd: "error", msg: "Customer not regsitered" })
      )
      break
    case "register":
      let { publicKey, privateKey } = getKeypair()
      msg.customerId = publicKey.toString("base64")
      msg.customerSecret = privateKey.toString("base64")
      hash = appendToTransactionLog(msg)
      socket.end(
        JSON.stringify({
          cmd: "register",
          msg: "Customer registered",
          customerId: msg.customerId,
          customerSecret: msg.customerSecret,
          hash: hash,
        })
      )
      break
    case "deposit":
      if (checkCustomerExists(msg.customerId)) {
        hash = appendToTransactionLog(msg)
        socket.end(
          JSON.stringify({
            cmd: "balance",
            balance: getBalance(msg.customerId),
            customerId: msg.customerId,
            hash: hash,
          })
        )
        break
      }
      socket.end(
        JSON.stringify({ cmd: "error", msg: "Customer not regsitered" })
      )
      break
    case "withdraw":
      if (checkCustomerExists(msg.customerId)) {
        const balance = getBalance(msg.customerId)
        if (-msg.amount <= balance) {
          hash = appendToTransactionLog(msg)
          socket.end({
            cmd: "balance",
            balance: getBalance(msg.customerId),
            customerId: msg.customerId,
            hash: hash,
          })
        } else {
          socket.end(
            JSON.stringify({ cmd: "error", msg: "Insufficient funds!" })
          )
        }
        break
      }
      socket.end(
        JSON.stringify({ cmd: "error", msg: "Customer not regsitered" })
      )
      break
    default:
      socket.end(JSON.stringify({ cmd: "error", msg: "Unknown command" }))
      break
  }
}

const validateSignature = msg => {
  let signature = new Buffer(msg.signature, "base64")
  let publicKey = new Buffer(msg.message.customerId, "base64")

  let lastHash = log
    .filter(item => item.value.customerId === msg.message.customerId)
    .pop().hash
  msg.message.lastHash = lastHash
  let message = Buffer.from(JSON.stringify(msg.message))
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

var server = net.createServer(function(socket) {
  socket = jsonStream(socket)

  socket.on("data", function(msg) {
    console.log("Bank received:", msg)

    if (msg.message.cmd !== "register") {
      if (validateSignature(msg)) {
        processCommand(msg.message, socket)
      } else {
        socket.end(
          JSON.stringify({ cmd: "error", msg: "Incorrect signature!" })
        )
      }
    } else {
      processCommand(msg.message, socket)
    }
  })
})

server.listen(3876)
