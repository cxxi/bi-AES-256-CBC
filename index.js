'use strict'

const crypto = require('crypto')


class Demo
{
	static encrypt(message)
	{
		try
		{
	    		if (process.versions.openssl <= '1.0.1f') {
		    		throw new Error('OpenSSL Version too old, vulnerability to Heartbleed')
			}

			let iv = crypto.randomBytes(crypto.getCipherInfo('AES-256-CBC').ivLength)
			let cipher = crypto.createCipheriv('AES-256-CBC', new Buffer(process.env.PRIVATE_KEY), iv)
			let encrypted = cipher.update(message)
			encrypted = Buffer.concat([encrypted, cipher.final()])

			return `${iv.toString('hex')}:${encrypted.toString('hex')}`
	    	} 

	    	catch(error)
	    	{
	    		console.error(error)
	    	}
	}

	static decrypt(hashedMessage)
	{
    		try
    		{
			let bin = hashedMessage.toString().split(':')
			let iv = new Buffer(bin.shift(), 'hex')
			let encryptedText = new Buffer(bin.join(':'), 'hex')
			let decipher = crypto.createDecipheriv('AES-256-CBC', new Buffer(process.env.PRIVATE_KEY), iv)
			let decrypted = decipher.update(encryptedText)

			decrypted = Buffer.concat([decrypted, decipher.final()])
			return decrypted.toString()
	    	}

	    	catch(error)
	    	{
	        	console.error(error)
	    	}
	}
}
