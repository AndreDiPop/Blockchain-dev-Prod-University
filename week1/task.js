var crypto = require('crypto');
var str = 'SLOZNA! SLOZNA!!';
var result = crypto.createHash('sha256').update(str).digest('hex');
console.log('str: ' + str + ", result: " + result);