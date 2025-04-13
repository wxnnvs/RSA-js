const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { modPow } = require("bigint-mod-arith");

const app = express();
const PORT = 3000;

// Middleware to serve static files
app.use(express.static(path.join(__dirname, "public")));

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Route to serve the main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Route to generate keys
app.get("/generate-keys", (req, res) => {
  const small_primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
  ];

  try {
    // generate 2 prime numbers
    const p = crypto.generatePrimeSync(1024, { bigint: true });
    const q = crypto.generatePrimeSync(1024, { bigint: true });

    // calculate n = p * q
    const n = p * q;

    // calculate phi(n) = (p - 1) * (q - 1)
    const phi = (p - 1n) * (q - 1n);

    // check whether phi can be divided by any small primes
    let e = 65537n; // commonly used prime number
    for (let i = 0; i < small_primes.length; i++) {
      if (phi % BigInt(small_primes[i]) !== 0n) {
        e = BigInt(small_primes[i]);
        break;
      }
    }

    // calculate d such that d * e ≡ 1 (mod phi)
    const d = modInverse(e, phi);
    if (d === NaN) {
      return res.status(500).send("Failed to calculate private key.");
    }

    // Add e and n to the public key
    const publicKeyNumber = e.toString() + "--" + n.toString();
    const publicKey64 = Buffer.from(publicKeyNumber).toString("base64");
    const publicKey64Formatted = publicKey64.match(/.{1,64}/g).join("\n");
    const publicKey =
      "-----BEGIN RSA-JS PUBLIC KEY BLOCK-----\n\n" +
      publicKey64Formatted +
      "\n\n-----END RSA-JS PUBLIC KEY BLOCK-----";

    // Add d and n to the private key
    const privateKeyNumber = d.toString() + "--" + n.toString();
    const privateKey64 = Buffer.from(privateKeyNumber).toString("base64");
    const privateKey64Formatted = privateKey64.match(/.{1,64}/g).join("\n");
    const privateKey =
      "-----BEGIN RSA-JS PRIVATE KEY BLOCK-----\n\n" +
      privateKey64Formatted +
      "\n\n-----END RSA-JS PRIVATE KEY BLOCK-----";

    return res.type("text/plain").send(`${publicKey}\n\n\n${privateKey}`);
  } catch (error) {
    return res.status(500).send("An error occurred: " + error.message);
  }
});

// Route to handle encryption form submission
app.post("/encrypt", (req, res) => {
  const { publicKey, message } = req.body;

  // Clean and decode the Base64 public key
  const publicKey64 = publicKey
    .replace(/-----BEGIN RSA-JS PUBLIC KEY BLOCK-----\s*/g, "")
    .replace(/-----END RSA-JS PUBLIC KEY BLOCK-----\s*/g, "")
    .replace(/\s+/g, ""); // Remove all whitespace

  try {
    // Decode the Base64 public key
    const publicKeyNumber = Buffer.from(publicKey64, "base64").toString("utf-8");

    // Extract e and n from the public key
    const [eStr, nStr] = publicKeyNumber.split("--");
    if (!eStr || !nStr) {
      throw new Error("Invalid public key format. Could not extract 'e' and 'n'.");
    }

    const e = BigInt(eStr);
    const n = BigInt(nStr);

    // Check if message is empty
    if (!message) {
      return res.status(400).send("Message cannot be empty.");
    }

    // Convert message to BigInt using hexadecimal encoding
    const messageHex = Buffer.from(message, "utf-8").toString("hex");
    const messageBigInt = BigInt("0x" + messageHex);

    // Encrypt the message using modular exponentiation
    const encryptedMessageBigInt = modPow(messageBigInt, e, n);

    // Convert the encrypted message to a hexadecimal string and encode it in Base64
    const encryptedMessageHex = encryptedMessageBigInt.toString(16);
    const encryptedMessage64 = Buffer.from(encryptedMessageHex, "hex").toString("base64");

    res.send(encryptedMessage64);
  } catch (error) {
    console.error("Error during encryption:", error);
    return res.status(400).send(error.message);
  }
});

// Route to handle decryption form submission
app.post("/decrypt", (req, res) => {
  const { privateKey, encryptedMessage } = req.body;

  // Clean and decode the Base64 private key
  const privateKey64 = privateKey
    .replace(/-----BEGIN RSA-JS PRIVATE KEY BLOCK-----\s*/g, "")
    .replace(/-----END RSA-JS PRIVATE KEY BLOCK-----\s*/g, "")
    .replace(/\s+/g, ""); // Remove all whitespace

  try {
    // Decode the Base64 private key
    const privateKeyNumber = Buffer.from(privateKey64, "base64").toString("utf-8");

    // Extract d and n from the private key
    const [dStr, nStr] = privateKeyNumber.split("--");
    if (!dStr || !nStr) {
      throw new Error("Invalid private key format. Could not extract 'd' and 'n'.");
    }

    const d = BigInt(dStr);
    const n = BigInt(nStr);

    // Check if encryptedMessage is empty
    if (!encryptedMessage) {
      return res.status(400).send("Encrypted message cannot be empty.");
    }

    // Decode the encrypted message from Base64 and interpret it as a hexadecimal string
    const encryptedMessageHex = Buffer.from(encryptedMessage, "base64").toString("hex");
    const encryptedMessageBigInt = BigInt("0x" + encryptedMessageHex);

    // Decrypt the message using modular exponentiation
    const decryptedMessageBigInt = modPow(encryptedMessageBigInt, d, n);

    // Convert the decrypted BigInt back to a UTF-8 string
    const decryptedMessageHex = decryptedMessageBigInt.toString(16);
    const decryptedMessage = Buffer.from(decryptedMessageHex, "hex").toString("utf-8");

    res.send(decryptedMessage);
  } catch (error) {
    console.error("Error during decryption:", error);
    return res.status(400).send(error.message);
  }
});

// modInverse function to calculate modular inverse
// taken and modified from https://stackoverflow.com/a/51562038
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  if (!a || m < 2n) {
    return NaN; // invalid input
  }
  // find the gcd
  const s = [];
  let b = m;
  while (b) {
    [a, b] = [b, a % b];
    s.push({ a, b });
  }
  if (a !== 1n) {
    return NaN; // inverse does not exist
  }
  // find the inverse
  let x = 1n;
  let y = 0n;
  for (let i = s.length - 2; i >= 0; --i) {
    [x, y] = [y, x - y * (s[i].a / s[i].b)];
  }
  return ((y % m) + m) % m;
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
