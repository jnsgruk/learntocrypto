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
// Read secret key from first argument
const secretKey = Buffer.from(argv[0], "base64")

// Function to traverse transaction log and return balance
const reduceLog = (balance, entry) => balance + entry.value.amount

// Hash input value and return string as hex
const hashToHex = value => {
  // Create output buffer
  let output = Buffer.alloc(sodium.crypto_generichash_BYTES)
  // Hash value and place output into buffer
  sodium.crypto_generichash(output, Buffer.from(value))
  // Output hex representation
  return output.toString("hex")
}
// Append a new transaction with its hash and value
const appendToTransactionLog = entry => {
  // Create generate hash in case this is the first entry
  const genesisHash = Buffer.alloc(32).toString("hex")
  // Get previous hash if exists, if not use genesis
  const previousHash = log.length ? log[log.length - 1].hash : genesisHash
  // Create buffer to store signature
  const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  // Create hash of previous hash + new entry
  const hash = hashToHex(previousHash + JSON.stringify(entry))
  // Sign the new hash using the private key specified as an argument
  sodium.crypto_sign_detached(signature, Buffer.from(hash), privateKey)
  // Add new entry to log
  log.push({
    value: entry,
    hash: hash,
    signature: signature.toString("base64"),
  })
  // Save transaction log to file
  writeTransactionLog()
  return hash
}

const writeTransactionLog = () => {
  // Get a JSON representation of the log dictionary
  let logString = JSON.stringify(log, null, 2)
  // Create a buffer for our nonce
  let nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
  // Generate nonce and place in buffer
  sodium.randombytes_buf(nonce)
  // Create cipher buffer
  let cipher = Buffer.alloc(logString.length + sodium.crypto_secretbox_MACBYTES)
  // Encrypt JSON version of log
  sodium.crypto_secretbox_easy(cipher, Buffer.from(logString), nonce, secretKey)
  // Create output dictionary with ciphertext and nonce
  let output = {
    cipherText: cipher.toString("base64"),
    nonce: nonce.toString("base64"),
  }
  // Write dictionary to JSON file
  fs.writeFileSync("./log.json", JSON.stringify(output, null, 2), "utf-8")
  // This is for debug only - write out decrpyted version
  fs.writeFileSync("./logDx.json", JSON.stringify(log, null, 2), "utf-8")
}

// Check the hash chain the log and exit if it's been messed with
const validateLogChain = log => {
  log.map((current, index, array) => {
    // First verify the hash is correct by re-generating and comparing
    // Use last hash if exists, if not use genesis hash
    let previousHash = index
      ? array[index - 1].hash
      : Buffer.alloc(32).toString("hex")
    // Regenerate hash of previous hash plus current block
    let hash = hashToHex(previousHash + JSON.stringify(current.value))
    // If hashes don't match, exit.
    return hash == current.hash ? true : process.exit(1)
    // Now hashes are correct, check that signature matches
    let signature = Buffer.from(current.signature, "base64")
    let correctSignature = sodium.crypto_sign_verify_detached(
      signature,
      Buffer.from(current.hash),
      publicKey
    )
    // Return true, or exit is signature is invalid
    return correctSignature ? true : process.exit(1)
  })
  console.log("Verified transaction log successfully!")
}

// Filter the log chain to ascertain whether a specific user has registered
const checkCustomerExists = customerId => {
  // Filter log to get register events for specific customerId
  return (
    log.filter(
      e => e.value.cmd === "register" && e.value.customerId === customerId
    ).length > 0
  )
}

const validateSignature = msg => {
  // Check if customer exists, return false if not
  if (!checkCustomerExists(msg.message.customerId)) return false
  // Decode signature/key and place into buffers
  let signature = Buffer.from(msg.signature, "base64")
  let publicKey = Buffer.from(msg.message.customerId, "base64")
  // Get the hash of the user's last logged transaction
  let lastHash = log
    .filter(item => item.value.customerId === msg.message.customerId)
    .pop().hash
  // Assign last hash into message
  // This combined with signing prevents replay attacks
  msg.message.lastHash = lastHash
  // Create a buffer from the JSON representation of the message
  let message = Buffer.from(JSON.stringify(msg.message))
  // Sign the message with the new hash appended
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

// Traverse log chain to get balance for a specific customer
const getBalance = customerId => {
  // Filter for all deposit/withdrawal events for a specific customer
  const balanceEvents = log.filter(
    e => e.value.cmd !== "register" && e.value.customerId === customerId
  )
  return balanceEvents.reduce(reduceLog, 0)
}

// Takes a log file in, and decrypts with specified secret key
const decryptFile = path => {
  // Check if logfile exists, if not return blank array
  if (!fs.existsSync(path)) return []
  // Import log in encrypted form
  const encrypted_log = require(path)
  // Create buffers containing the ciphertext and nonce from the log file
  const cipher = Buffer.from(encrypted_log.cipherText, "base64")
  const nonce = Buffer.from(encrypted_log.nonce, "base64")
  // Create a buffer for the decrypted log
  let logString = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
  // Decrypt the log using secret key provided as an argument
  var success = sodium.crypto_secretbox_open_easy(
    logString,
    cipher,
    nonce,
    secretKey
  )
  // Display a message
  console.log(
    success ? "Log file decrypted!" : "Log file could not be decrypted!"
  )
  // Return decrypted log is success, else exit
  return success ? JSON.parse(logString.toString()) : process.exit(1)
}

const generateKeypair = () => {
  // Create buffers for both keys
  let publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  let privateKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  // Generate keys and store in relevant buffers
  sodium.crypto_sign_keypair(publicKey, privateKey)
  return { publicKey, privateKey }
}

// Load keys from file, or generate and store keys in file if none exist
const getKeys = path => {
  // Check that file actually exists
  if (fs.existsSync(path)) {
    // Load keys from file
    let { publicKey, privateKey } = require("./keys.json")
    // Place keys in Buffers, decoding from base64
    publicKey = Buffer.from(publicKey, "base64")
    privateKey = Buffer.from(privateKey, "base64")
    console.log("Loaded public/private key pair from " + path)
    // Return dictionary for easy assignment
    return { privateKey, publicKey }
  } else {
    let { publicKey, privateKey } = generateKeypair()
    // Write newly generated keys into file for next time
    fs.writeFileSync(
      path,
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
    // Output a status message
    console.log("Created new public/private key pair stored in " + path)
    // Return dictionary for easy assignment
    return { privateKey, publicKey }
  }
}

const processCommand = msg => {
  let hash = null

  switch (msg.cmd) {
    case "register":
      // Generate the user a public key (user id) and secret key
      let { publicKey, privateKey } = generateKeypair()
      // Set the relevant message parameters with the keys
      msg.customerId = publicKey.toString("base64")
      // Write message to log and get the hash
      hash = appendToTransactionLog(msg)
      // Send the result to the user
      return {
        cmd: "register",
        msg: "Customer registered",
        customerId: msg.customerId,
        customerSecret: privateKey.toString("base64"),
        hash: hash,
      }
    case "balance":
      // Send them their balance
      return {
        cmd: "balance",
        balance: getBalance(msg.customerId),
      }
    case "deposit":
      // Add transation to the log and get the hash
      hash = appendToTransactionLog(msg)
      // Send the result to the user
      return {
        cmd: "balance",
        balance: getBalance(msg.customerId),
        customerId: msg.customerId,
        hash: hash,
      }
    case "withdraw":
      // Get user's current balance
      const balance = getBalance(msg.customerId)
      // Ensure they're onyl withdrawing what they have!
      if (-msg.amount <= balance) {
        // If valid, add to log and return hash
        hash = appendToTransactionLog(msg)
        // Send the user the result
        return {
          cmd: "balance",
          balance: getBalance(msg.customerId),
          customerId: msg.customerId,
          hash: hash,
        }
      } else {
        return { cmd: "error", msg: "Insufficient funds!" }
      }
    default:
      return { cmd: "error", msg: "Unknown command" }
  }
}

const socketSend = (socket, message) => socket.end(JSON.stringify(message))

// Get and decrypt log file on disk (if exists)
let log = decryptFile("./log.json")
// Validate the hash chain and signatures to ensure integrity
validateLogChain(log)
// Load or generate private/public key pair
let { privateKey, publicKey } = getKeys("./keys.json")

var server = net.createServer(function(socket) {
  s = jsonStream(socket)
  s.on("data", function(msg) {
    console.log(msg)
    // For all operations other than register, validate signature
    if (msg.message.cmd !== "register" && !validateSignature(msg)) {
      socketSend(s, {
        cmd: "error",
        msg:
          "Check user ID! Signature invalid! Are you trying to replay a message?",
      })
    } else {
      socketSend(s, processCommand(msg.message))
    }
  })
})

server.listen(3876)
