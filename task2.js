const crypto = require('crypto');
const secp256k1 = require('secp256k1');

const initVector = crypto.randomBytes(16);
algo = "aes-256-cbc"
const msg = process.argv[2]; // сообщение, которое я подпишу
const digested = digest(msg);
console.log(`0) Andre's message:
message: ${msg}
message digest: ${digested.toString('hex')}`);

// сделать приватныйКлюч

function digest(str, algo = 'sha256') {
    return crypto.createHash(algo).update(str).digest();
}

let privateKey;
do {
    privateKey = crypto.randomBytes(32); // тут берутся рандомное значние 32 байтов
} while (!secp256k1.privateKeyVerify(privateKey)); // они берутся пока не сгенерируется приватный ключ из кривых

// получить публичный ключ в каком-то компрессном формате
const publicKey = secp256k1.publicKeyCreate(privateKey);

console.log(`1) Andre aquired new keypair:
publicKey: ${Buffer.from(publicKey).toString('hex')}
privateKey: ${Buffer.from(privateKey).toString('hex')}`);

console.log(`2) Andre signed his message digest with his privateKey to get its signature:`);

const sigObj = secp256k1.ecdsaSign(digested, privateKey); 

// создаем объект подписи на базе элептической кривой 
//  и подписываем объект дайджест, который мы получили. Подписываем мы хэш. Мы с помощью приватного ключа
// зашифровываем хеш сообщения. Ер 1 мь он будет 100 лет шифровать, не знаю почему

const sig = sigObj.signature;
console.log(" Signature:", Buffer.from(sig).toString('hex'));

const digest_bad = digest("buy");

console.log(`3) BOb verifyed by 3 elements ("message digest", 'signature', and Andre's "publicKey"):`);
let verified = secp256k1.ecdsaVerify(sig, digested, publicKey);
console.log(' verified:', verified);


// Боб получает сообщение hi, считаешь от него дайджест, потом он берет подпись, которую Андре ему переслал
// и


// далее зашифрую и расшифрую

const cipher = crypto.createCipheriv(algo, privateKey, initVector);

let encryptedData = cipher.update(msg, "utf-8", "hex");

encryptedData += cipher.final("hex");

console.log("Encrypted message: " + encryptedData);

// the decipher function
const decipher = crypto.createDecipheriv(algo, privateKey, initVector);

let decryptedData = decipher.update(encryptedData, "hex", "utf-8");

decryptedData += decipher.final("utf8");

console.log("Decrypted message: " + decryptedData);