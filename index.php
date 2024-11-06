<?php

class Demo
{
	public static function encrypt(string $message): string
	{
		try
		{
		    	if (OPENSSL_VERSION_NUMBER <= 268443727) {
				throw new RuntimeException('OpenSSL Version too old, vulnerability to Heartbleed');
		    	}

			$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
		    
			$ciphertext = openssl_encrypt($message, 'AES-256-CBC', $_ENV['PRIVATE_KEY'], OPENSSL_RAW_DATA, $iv);

			$hashedMessage = implode(':', [ bin2hex($iv), bin2hex($ciphertext) ]);

			return $hashedMessage;
		}

		catch(\Exception $exception)
		{
			echo $exception->getMessage().PHP_EOL;
		}
	}

	public static function decrypt(string $hashedMessage): string
	{
		try
		{
			[ $iv, $ciphertext ] = array_map(fn($hex) => hex2bin($hex), explode(":", $hashedMessage));
		 
			$message = openssl_decrypt($ciphertext, 'AES-256-CBC', $_ENV['PRIVATE_KEY'], OPENSSL_RAW_DATA, $iv);

			return $message;
		}

		catch(\Exception $exception)
		{
			echo $exception->getMessage().PHP_EOL;
		}
	}
}
