import chalk from "chalk"
import clear from "clear"
import figlet from "figlet"
import inquirer from "inquirer"
import crypto from "crypto"
import fs from "fs"

async function encryptText() {
    var { text } = await (inquirer.prompt([{ type: 'input', name: 'text', message: 'What text would you like to encrypt?' }]))
    var plainText = text
    return crypto.publicEncrypt({
        key: fs.readFileSync('public_key.pem', 'utf8'),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    },
  // We convert the data string to a buffer
    Buffer.from(plainText)
    )
}

async function decryptText() {
    var { text } = await (inquirer.prompt([{ type: 'input', name: 'text', message: 'What would you like to decrypt?' }]))
    var encryptedText = Buffer.from(text, 'base64')
    return crypto.privateDecrypt(
    {
        key: fs.readFileSync('private_key.pem', 'utf8'),
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    },
    encryptedText
    )
}

async function asymmetric() {
    inquirer.prompt([{
        type: 'list',
        name: 'ed',
        message: 'Would you like to encrypt or decrypt?',
        choices: ['Encrypt', 'Decrypt']
    }])
        .then(async answers => {
            if (answers.ed === "Encrypt") {
                var encryptedText = await encryptText()
                console.log('The text encrypted is: \n',encryptedText.toString('base64'))
            }
            else if (answers.ed === "Decrypt") {
                var decryptedText = await decryptText()
                console.log("The decrypted text is: \n", decryptedText.toString())
            }
    })
}

async function hashText() {
    var { text } = await (inquirer.prompt([{ type: 'input', name: 'text', message: 'What would you like to hash?' }]))
    const hash = crypto.createHash('sha256')
    hash.update(text)
    return hash.digest("base64")
}

async function checkHash() {
    const hash = crypto.createHash('sha256')
    var Ohash = null
    await (inquirer.prompt([{ type: 'input', name: 'hash', message: 'What is the hash?' }])).then(answers => {Ohash = answers.hash})
    await (inquirer.prompt([{ type: 'input', name: 'text', message: 'What would you like to check?' }])).then(answers => { hash.update(answers.text) })
    return (hash.digest("base64") == Ohash)
}

async function hashes() {
        inquirer.prompt([{
        type: 'list',
        name: 'ed',
        message: 'Would you like to hash or check?',
        choices: ['Hash', 'Check']
    }])
        .then(async answers => {
            if (answers.ed === "Hash") {
                var hashT = await hashText()
                console.log('The hash is: \n',hashT)
            }
            else if (answers.ed === "Check") {
                console.log(await checkHash() ? "Correct!" : "Incorrect.")
            }
    })
}

clear()

console.log(chalk.greenBright(figlet.textSync('Cryptography!', { horizontalLayout: 'full' })))

inquirer
    .prompt([{
        type: 'list',
        name: 'goal',
        message: 'What would you like to do?',
        choices: ['Asymmetric encryption', 'Hash']
    }])
    .then(async answers => {
        if (answers.goal === "Asymmetric encryption") {
            await asymmetric()
        }
        else if (answers.goal === "Hash") {
            hashes()
        }
    })