#include "MainForm.h"

using namespace EncryptionTool;

// ===== ORIGINAL UI CODE =====

// Initialize encryption when algorithm changes
void MainForm::InitializeEncryption()
{
	if (comboBox1->Items->Count == 0)
	{
		for each (String ^ algo in encryptionAlgorithms)
		{
			comboBox1->Items->Add(algo);
		}
		comboBox1->SelectedIndex = 0;
	}

	UpdateKeyInfo();

	int ivSize = 16;
	String^ algorithm = comboBox1->SelectedItem->ToString();
	if (algorithm == "ChaCha20")
	{
		ivSize = 12;
	}
	else if (algorithm == "RC4")
	{
		ivSize = 0;
	}
	else if (algorithm == "3DES" || algorithm == "Blowfish")
	{
		ivSize = 8; // 3DES and Blowfish require 8-byte IV
	}

	if (algorithm == "RSA")
	{
		// Hide symmetric key controls, show RSA controls
		label3->Visible = false;
		textBoxKey->Visible = false;
		panelKeyType->Visible = false;
		buttonGenerateKey->Visible = false;
		panelRSAKeys->Visible = true;
		panelECCKeys->Visible = false;

		// Position buttons differently for RSA
		button1->Location = System::Drawing::Point(320, 295);
		button2->Location = System::Drawing::Point(440, 295);

		label4->Text = "Key: RSA 2048-bit";
		label5->Text = "IV: Not used for RSA";
	}
	else if (algorithm == "ECC-256")
	{
		// Hide symmetric key controls, show ECC controls
		label3->Visible = false;
		textBoxKey->Visible = false;
		panelKeyType->Visible = false;
		buttonGenerateKey->Visible = false;
		panelRSAKeys->Visible = false;
		panelECCKeys->Visible = true;

		// Position buttons differently for ECC
		button1->Location = System::Drawing::Point(320, 295);
		button2->Location = System::Drawing::Point(440, 295);

		label4->Text = "Key: ECC P-256 (256-bit)";
		label5->Text = "IV: Not used for ECC";
	}
	else
	{
		// Show symmetric key controls, hide RSA and ECC controls
		label3->Visible = true;
		textBoxKey->Visible = true;
		panelKeyType->Visible = true;
		buttonGenerateKey->Visible = true;
		panelRSAKeys->Visible = false;
		panelECCKeys->Visible = false;

		// Position buttons back for symmetric algorithms
		button1->Location = System::Drawing::Point(320, 200);
		button2->Location = System::Drawing::Point(440, 200);

		if (ivSize > 0)
		{
			iv = GenerateRandomIV(ivSize);
			label5->Text = "IV: " + iv;
		}
		else
		{
			iv = "";
			label5->Text = "IV: Not used for RC4";
		}
	}
}

void MainForm::UpdateKeyInfo()
{
	String^ algorithm = comboBox1->SelectedItem->ToString();

	if (algorithm == "RSA")
	{
		labelKeyInfo->Text = "RSA 2048-bit (Public/Private Key Pair)";
		labelKeyInfo->ForeColor = Color::DarkGreen;
		return;
	}
	else if (algorithm == "ECC-256")
	{
		labelKeyInfo->Text = "ECC P-256 (256-bit Public/Private Key Pair)";
		labelKeyInfo->ForeColor = Color::DarkGreen;
		return;
	}

	String^ keyText = textBoxKey->Text;

	if (String::IsNullOrEmpty(keyText))
	{
		labelKeyInfo->Text = "Enter key or click Generate Key";
		labelKeyInfo->ForeColor = Color::DarkRed;
		label4->Text = "Key: [Not Set]";
		return;
	}

	try
	{
		array<Byte>^ keyBytes = GetKeyBytesFromInput();
		String^ keyInfo = GetKeySizeInfo(algorithm, keyBytes);
		labelKeyInfo->Text = keyInfo;

		if (ValidateKeySize(algorithm, keyBytes))
		{
			labelKeyInfo->ForeColor = Color::DarkGreen;
			label4->Text = "Key: " + keyInfo;
		}
		else
		{
			labelKeyInfo->ForeColor = Color::DarkRed;
			label4->Text = "Key: " + keyInfo + " - INVALID";
		}
	}
	catch (Exception^ ex)
	{
		labelKeyInfo->Text = "Invalid key format: " + ex->Message;
		labelKeyInfo->ForeColor = Color::DarkRed;
		label4->Text = "Key: Invalid format";
	}
}

bool MainForm::ValidateKeySize(String^ algorithm, array<Byte>^ keyBytes)
{
	int keySizeBits = keyBytes->Length * 8;

	if (algorithm == "AES")
	{
		return (keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256);
	}
	else if (algorithm == "RC4")
	{
		return (keySizeBits >= 40 && keySizeBits <= 2048);
	}
	else if (algorithm == "ChaCha20")
	{
		return (keySizeBits == 128 || keySizeBits == 256);
	}
	else if (algorithm == "Blowfish")
	{
		return (keySizeBits >= 32 && keySizeBits <= 448 && keySizeBits % 8 == 0);
	}
	else if (algorithm == "3DES")
	{
		return (keySizeBits == 128 || keySizeBits == 192);
	}
	else if (algorithm == "RSA" || algorithm == "ECC-256")
	{
		return true; // These use key pairs, not symmetric keys
	}

	return false;
}

String^ MainForm::GetKeySizeInfo(String^ algorithm, array<Byte>^ keyBytes)
{
	int keySizeBits = keyBytes->Length * 8;
	String^ sizeInfo = keySizeBits + " bit (" + keyBytes->Length + " bytes)";

	if (algorithm == "AES")
	{
		if (keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256)
			return sizeInfo + " - Valid for AES";
		else
			return sizeInfo + " - Invalid: AES requires 128, 192, or 256 bits";
	}
	else if (algorithm == "RC4")
	{
		if (keySizeBits >= 40 && keySizeBits <= 2048)
			return sizeInfo + " - Valid for RC4";
		else
			return sizeInfo + " - Invalid: RC4 requires 40-2048 bits";
	}
	else if (algorithm == "ChaCha20")
	{
		if (keySizeBits == 128 || keySizeBits == 256)
			return sizeInfo + " - Valid for ChaCha20";
		else
			return sizeInfo + " - Invalid: ChaCha20 requires 128 or 256 bits";
	}
	else if (algorithm == "Blowfish")
	{
		if (keySizeBits >= 32 && keySizeBits <= 448 && keySizeBits % 8 == 0)
			return sizeInfo + " - Valid for Blowfish";
		else
			return sizeInfo + " - Invalid: Blowfish requires 32-448 bits (multiples of 8)";
	}
	else if (algorithm == "3DES")
	{
		if (keySizeBits == 128)
			return sizeInfo + " - Valid for 3DES (2-key)";
		else if (keySizeBits == 192)
			return sizeInfo + " - Valid for 3DES (3-key)";
		else
			return sizeInfo + " - Invalid: 3DES requires 128 or 192 bits";
	}
	else if (algorithm == "RSA")
	{
		return "RSA 2048-bit (Public/Private Key Pair)";
	}
	else if (algorithm == "ECC-256")
	{
		return "ECC P-256 (256-bit Public/Private Key Pair)";
	}

	return sizeInfo + " - Unknown algorithm";
}

array<Byte>^ MainForm::GetKeyBytesFromInput()
{
	String^ keyText = textBoxKey->Text;

	if (radioHexKey->Checked)
	{
		keyText = keyText->Replace(" ", "")->Replace("-", "")->Replace(":", "");

		if (keyText->Length % 2 != 0)
			throw gcnew ArgumentException("Hex key must have even number of characters");

		for (int i = 0; i < keyText->Length; i++)
		{
			if (!Char::IsDigit(keyText[i]) && !(keyText[i] >= 'A' && keyText[i] <= 'F') && !(keyText[i] >= 'a' && keyText[i] <= 'f'))
				throw gcnew ArgumentException("Invalid hex character in key");
		}

		array<Byte>^ keyBytes = gcnew array<Byte>(keyText->Length / 2);
		for (int i = 0; i < keyBytes->Length; i++)
		{
			String^ byteString = keyText->Substring(i * 2, 2);
			keyBytes[i] = Byte::Parse(byteString, System::Globalization::NumberStyles::HexNumber);
		}
		return keyBytes;
	}
	else
	{
		return Encoding::UTF8->GetBytes(keyText);
	}
}

String^ MainForm::GenerateRandomKey(int size)
{
	array<Byte>^ randomBytes = gcnew array<Byte>(size);
	RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
	rng->GetBytes(randomBytes);

	if (radioHexKey->Checked)
	{
		return BitConverter::ToString(randomBytes)->Replace("-", "");
	}
	else
	{
		return Convert::ToBase64String(randomBytes);
	}
}

String^ MainForm::GenerateRandomIV(int size)
{
	array<Byte>^ randomBytes = gcnew array<Byte>(size);
	RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
	rng->GetBytes(randomBytes);
	return Convert::ToBase64String(randomBytes);
}

// Event Handlers
void MainForm::button1_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		String^ plainText = textBox1->Text;
		String^ algorithm = comboBox1->SelectedItem->ToString();

		if (String::IsNullOrEmpty(plainText) || plainText == "Enter your text here...")
		{
			MessageBox::Show(L"Please enter text to encrypt.");
			return;
		}

		if (algorithm == "RSA")
		{
			// RSA encryption
			String^ publicKeyText = textBoxPublicKey->Text;
			if (String::IsNullOrEmpty(publicKeyText))
			{
				MessageBox::Show(L"Please enter or generate RSA public key.");
				return;
			}

			// Check message length
			array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plainText);

			// For 2048-bit RSA with OAEP SHA-1 padding, max message size is 214 bytes
			if (plainBytes->Length > 214)
			{
				MessageBox::Show(L"Message too long for RSA 2048-bit. Maximum size is about 214 characters.",
					"Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}

			BigInteger n, e;
			if (!ImportPublicKeyFromPEM(publicKeyText, n, e))
			{
				MessageBox::Show(L"Invalid public key format. Please use PEM format.");
				return;
			}

			array<Byte>^ encryptedBytes = RSA_Encrypt(plainBytes, n, e);
			String^ encryptedText = Convert::ToBase64String(encryptedBytes);

			richTextBox1->Text = "ENCRYPTED TEXT (RSA 2048-bit):\r\n" + encryptedText;
			richTextBox1->ForeColor = Color::DarkGreen;
		}
		else if (algorithm == "ECC-256")
		{
			// ECC encryption
			String^ publicKeyText = textBoxECCPublicKey->Text;
			if (String::IsNullOrEmpty(publicKeyText))
			{
				MessageBox::Show(L"Please enter or generate ECC public key.");
				return;
			}

			// Check message length
			array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plainText);

			// For ECC-256 with simple encryption, limit message size
			if (plainBytes->Length > 30) // Conservative limit for ECC-256
			{
				MessageBox::Show(L"Message too long for ECC-256. Maximum size is about 30 characters.",
					"Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}

			ECCPoint^ publicKey;
			if (!ImportECCPublicKeyFromPEM(publicKeyText, publicKey))
			{
				MessageBox::Show(L"Invalid ECC public key format. Please use PEM format.");
				return;
			}

			array<Byte>^ encryptedBytes = ECC_Encrypt(plainBytes, publicKey);
			String^ encryptedText = Convert::ToBase64String(encryptedBytes);

			richTextBox1->Text = "ENCRYPTED TEXT (ECC P-256):\r\n" + encryptedText;
			richTextBox1->ForeColor = Color::DarkGreen;
		}
		else
		{
			// Symmetric encryption
			String^ keyText = textBoxKey->Text;

			if (String::IsNullOrEmpty(keyText))
			{
				MessageBox::Show(L"Please enter a key or generate one.");
				return;
			}

			array<Byte>^ keyBytes = GetKeyBytesFromInput();
			if (!ValidateKeySize(algorithm, keyBytes))
			{
				MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}

			String^ encryptedText = EncryptString(plainText, algorithm);
			richTextBox1->Text = "ENCRYPTED TEXT (" + algorithm + " - " + GetKeySizeInfo(algorithm, keyBytes) + "):\r\n" + encryptedText;
			richTextBox1->ForeColor = Color::DarkGreen;
		}
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("Encryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::button2_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		String^ inputText = textBox1->Text;
		String^ algorithm = comboBox1->SelectedItem->ToString();

		if (String::IsNullOrEmpty(inputText) || inputText == "Enter your text here...")
		{
			MessageBox::Show(L"Please enter text to decrypt.");
			return;
		}

		if (algorithm == "RSA")
		{
			// RSA decryption
			String^ privateKeyText = textBoxPrivateKey->Text;
			if (String::IsNullOrEmpty(privateKeyText))
			{
				MessageBox::Show(L"Please enter RSA private key.");
				return;
			}

			try
			{
				// Extract clean Base64 from input
				String^ cipherText = inputText->Trim();

				// Remove label if present
				if (cipherText->Contains("ENCRYPTED TEXT (RSA 2048-bit):"))
				{
					int labelStart = cipherText->IndexOf("ENCRYPTED TEXT (RSA 2048-bit):");
					int newlineIndex = cipherText->IndexOf("\r\n", labelStart);
					if (newlineIndex != -1)
					{
						cipherText = cipherText->Substring(newlineIndex + 2);
					}
				}

				// Clean the Base64 string
				cipherText = cipherText->Replace(" ", "")->Replace("\r", "")->Replace("\n", "")->Replace("\t", "")
					->Replace("[", "")->Replace("]", "");

				// Keep only valid Base64 characters
				StringBuilder^ cleanBase64 = gcnew StringBuilder();
				for each (Char c in cipherText)
				{
					if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
						(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
					{
						cleanBase64->Append(c);
					}
				}

				cipherText = cleanBase64->ToString();

				// Ensure proper padding
				while (cipherText->Length % 4 != 0)
				{
					cipherText += "=";
				}

				// Convert from Base64
				array<Byte>^ cipherBytes;
				try
				{
					cipherBytes = Convert::FromBase64String(cipherText);
				}
				catch (FormatException^ ex)
				{
					MessageBox::Show("Invalid Base64 format. Please ensure you copied the entire encrypted text.\n\nError: " + ex->Message,
						"Base64 Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
					return;
				}

				// Import private key
				BigInteger n, e, d, p, q;
				if (!ImportPrivateKeyFromPEM(privateKeyText, n, e, d, p, q))
				{
					MessageBox::Show(L"Invalid private key format. Please use proper PEM format.");
					return;
				}

				// Decrypt
				array<Byte>^ decryptedBytes = RSA_Decrypt(cipherBytes, n, d);

				if (decryptedBytes == nullptr || decryptedBytes->Length == 0)
				{
					MessageBox::Show("Decryption produced no data.",
						"Decryption Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
					return;
				}

				// Convert to string
				String^ decryptedText = Encoding::UTF8->GetString(decryptedBytes);

				richTextBox1->Text = "DECRYPTED TEXT (RSA 2048-bit):\r\n" + decryptedText;
				richTextBox1->ForeColor = Color::DarkBlue;
			}
			catch (Exception^ ex)
			{
				MessageBox::Show("RSA Decryption failed: " + ex->Message +
					"\n\nCommon issues:\n" +
					"1. Wrong private key\n" +
					"2. Corrupted ciphertext\n" +
					"3. Key mismatch",
					"Decryption Error",
					MessageBoxButtons::OK,
					MessageBoxIcon::Error);
			}
		}
		else if (algorithm == "ECC-256")
		{
			// ECC decryption
			String^ privateKeyText = textBoxECCPrivateKey->Text;
			if (String::IsNullOrEmpty(privateKeyText))
			{
				MessageBox::Show(L"Please enter ECC private key.");
				return;
			}

			try
			{
				// Extract clean Base64 from input
				String^ cipherText = inputText->Trim();

				// Remove label if present
				if (cipherText->Contains("ENCRYPTED TEXT (ECC P-256):"))
				{
					int labelStart = cipherText->IndexOf("ENCRYPTED TEXT (ECC P-256):");
					int newlineIndex = cipherText->IndexOf("\r\n", labelStart);
					if (newlineIndex != -1)
					{
						cipherText = cipherText->Substring(newlineIndex + 2);
					}
				}

				// Clean the Base64 string
				cipherText = cipherText->Replace(" ", "")->Replace("\r", "")->Replace("\n", "")->Replace("\t", "")
					->Replace("[", "")->Replace("]", "");

				// Keep only valid Base64 characters
				StringBuilder^ cleanBase64 = gcnew StringBuilder();
				for each (Char c in cipherText)
				{
					if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
						(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
					{
						cleanBase64->Append(c);
					}
				}

				cipherText = cleanBase64->ToString();

				// Ensure proper padding
				while (cipherText->Length % 4 != 0)
				{
					cipherText += "=";
				}

				// Convert from Base64
				array<Byte>^ cipherBytes;
				try
				{
					cipherBytes = Convert::FromBase64String(cipherText);
				}
				catch (FormatException^ ex)
				{
					MessageBox::Show("Invalid Base64 format. Please ensure you copied the entire encrypted text.\n\nError: " + ex->Message,
						"Base64 Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
					return;
				}

				// Import private key
				BigInteger privateKey;
				if (!ImportECCPrivateKeyFromPEM(privateKeyText, privateKey))
				{
					MessageBox::Show(L"Invalid ECC private key format. Please use proper PEM format.");
					return;
				}

				// Decrypt
				array<Byte>^ decryptedBytes = ECC_Decrypt(cipherBytes, privateKey);

				if (decryptedBytes == nullptr || decryptedBytes->Length == 0)
				{
					MessageBox::Show("Decryption produced no data.",
						"Decryption Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
					return;
				}

				// Convert to string
				String^ decryptedText = Encoding::UTF8->GetString(decryptedBytes);

				richTextBox1->Text = "DECRYPTED TEXT (ECC P-256):\r\n" + decryptedText;
				richTextBox1->ForeColor = Color::DarkBlue;
			}
			catch (Exception^ ex)
			{
				MessageBox::Show("ECC Decryption failed: " + ex->Message +
					"\n\nCommon issues:\n" +
					"1. Wrong private key\n" +
					"2. Corrupted ciphertext\n" +
					"3. Key mismatch",
					"Decryption Error",
					MessageBoxButtons::OK,
					MessageBoxIcon::Error);
			}
		}
		else
		{
			// Symmetric decryption
			String^ keyText = textBoxKey->Text;

			if (String::IsNullOrEmpty(keyText))
			{
				MessageBox::Show(L"Please enter a key or generate one.");
				return;
			}

			array<Byte>^ keyBytes = GetKeyBytesFromInput();
			if (!ValidateKeySize(algorithm, keyBytes))
			{
				MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
				return;
			}

			String^ decryptedText = DecryptString(inputText, algorithm);
			richTextBox1->Text = "DECRYPTED TEXT (" + algorithm + " - " + GetKeySizeInfo(algorithm, keyBytes) + "):\r\n" + decryptedText;
			richTextBox1->ForeColor = Color::DarkBlue;
		}
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("Decryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::button3_Click(System::Object^ sender, System::EventArgs^ e)
{
	OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
	openFileDialog->Filter = "All files (*.*)|*.*";
	openFileDialog->Title = "Select file to encrypt/decrypt";
	if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		textBox2->Text = openFileDialog->FileName;
	}
}

void MainForm::button4_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		String^ inputFile = textBox2->Text;
		String^ algorithm = comboBox1->SelectedItem->ToString();

		if (String::IsNullOrEmpty(inputFile) || !File::Exists(inputFile) || inputFile == "Select a file...")
		{
			MessageBox::Show(L"Please select a valid file to encrypt.");
			return;
		}

		if (algorithm == "RSA" || algorithm == "ECC-256")
		{
			MessageBox::Show(L"" + algorithm + " is not suitable for large file encryption. Please use hybrid encryption (" + algorithm + " for key, AES for data).", "Info", MessageBoxButtons::OK, MessageBoxIcon::Information);
			return;
		}

		String^ keyText = textBoxKey->Text;
		if (String::IsNullOrEmpty(keyText))
		{
			MessageBox::Show(L"Please enter a key or generate one.");
			return;
		}

		array<Byte>^ keyBytes = GetKeyBytesFromInput();
		if (!ValidateKeySize(algorithm, keyBytes))
		{
			MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
			return;
		}

		String^ outputFile = Path::Combine(Path::GetDirectoryName(inputFile),
			Path::GetFileNameWithoutExtension(inputFile) + "_encrypted" + Path::GetExtension(inputFile));

		if (EncryptFile(inputFile, outputFile, algorithm))
		{
			richTextBox1->Text = "FILE ENCRYPTED SUCCESSFULLY!\r\nAlgorithm: " + algorithm +
				" (" + GetKeySizeInfo(algorithm, keyBytes) + ")\r\nInput: " + inputFile + "\r\nOutput: " + outputFile;
			richTextBox1->ForeColor = Color::DarkGreen;
		}
		else
		{
			MessageBox::Show(L"File encryption failed.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("File encryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::button5_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		String^ inputFile = textBox2->Text;
		String^ algorithm = comboBox1->SelectedItem->ToString();

		if (String::IsNullOrEmpty(inputFile) || !File::Exists(inputFile) || inputFile == "Select a file...")
		{
			MessageBox::Show(L"Please select a valid file to decrypt.");
			return;
		}

		if (algorithm == "RSA" || algorithm == "ECC-256")
		{
			MessageBox::Show(L"" + algorithm + " is not suitable for large file decryption. Please use hybrid encryption (" + algorithm + " for key, AES for data).", "Info", MessageBoxButtons::OK, MessageBoxIcon::Information);
			return;
		}

		String^ keyText = textBoxKey->Text;
		if (String::IsNullOrEmpty(keyText))
		{
			MessageBox::Show(L"Please enter a key or generate one.");
			return;
		}

		array<Byte>^ keyBytes = GetKeyBytesFromInput();
		if (!ValidateKeySize(algorithm, keyBytes))
		{
			MessageBox::Show(L"Invalid key size for selected algorithm. Please check the key information.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
			return;
		}

		String^ outputFile = Path::Combine(Path::GetDirectoryName(inputFile),
			Path::GetFileNameWithoutExtension(inputFile) + "_decrypted" + Path::GetExtension(inputFile));

		if (DecryptFile(inputFile, outputFile, algorithm))
		{
			richTextBox1->Text = "FILE DECRYPTED SUCCESSFULLY!\r\nAlgorithm: " + algorithm +
				" (" + GetKeySizeInfo(algorithm, keyBytes) + ")\r\nInput: " + inputFile + "\r\nOutput: " + outputFile;
			richTextBox1->ForeColor = Color::DarkBlue;
		}
		else
		{
			MessageBox::Show(L"File decryption failed.", "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("File decryption failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::comboBox1_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e)
{
	InitializeEncryption();
	UpdateKeyInfo();
}

void MainForm::textBoxKey_TextChanged(System::Object^ sender, System::EventArgs^ e)
{
	UpdateKeyInfo();
}

void MainForm::buttonGenerateKey_Click(System::Object^ sender, System::EventArgs^ e)
{
	String^ algorithm = comboBox1->SelectedItem->ToString();
	int keySizeBytes = 32;

	if (algorithm == "AES")
	{
		keySizeBytes = 16;
	}
	else if (algorithm == "RC4")
	{
		keySizeBytes = 16;
	}
	else if (algorithm == "ChaCha20")
	{
		keySizeBytes = 32;
	}
	else if (algorithm == "Blowfish")
	{
		keySizeBytes = 32;
	}
	else if (algorithm == "3DES")
	{
		keySizeBytes = 24; // Generate 24-byte key for 3DES (168-bit)
	}

	textBoxKey->Text = GenerateRandomKey(keySizeBytes);
}

void MainForm::buttonGenerateRSAKeys_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		richTextBox1->Text = "Generating RSA 2048-bit key pair... This may take a few seconds.";
		richTextBox1->ForeColor = Color::DarkBlue;
		Application::DoEvents(); // Update UI

		currentRSAKeyPair = GenerateRSAKeyPair(2048);

		// Export to PEM format
		String^ publicKeyPEM = ExportPublicKeyToPEM(currentRSAKeyPair->n, currentRSAKeyPair->e);
		String^ privateKeyPEM = ExportPrivateKeyToPEM(currentRSAKeyPair->n, currentRSAKeyPair->e,
			currentRSAKeyPair->d, currentRSAKeyPair->p, currentRSAKeyPair->q);

		textBoxPublicKey->Text = publicKeyPEM;
		textBoxPrivateKey->Text = privateKeyPEM;

		richTextBox1->Text = "RSA 2048-bit key pair generated successfully!\r\n\r\n" +
			"Public Key (PEM): " + publicKeyPEM->Substring(0, Math::Min(100, publicKeyPEM->Length)) + "...\r\n" +
			"Private Key (PEM): " + privateKeyPEM->Substring(0, Math::Min(100, privateKeyPEM->Length)) + "...";
		richTextBox1->ForeColor = Color::DarkGreen;
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("RSA key generation failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::buttonGenerateECCKeys_Click(System::Object^ sender, System::EventArgs^ e)
{
	try
	{
		richTextBox1->Text = "Generating ECC P-256 key pair...";
		richTextBox1->ForeColor = Color::DarkBlue;
		Application::DoEvents(); // Update UI

		currentECCKeyPair = GenerateECCKeyPair();

		// Export to PEM format
		String^ publicKeyPEM = ExportECCPublicKeyToPEM(currentECCKeyPair->publicKey);
		String^ privateKeyPEM = ExportECCPrivateKeyToPEM(currentECCKeyPair->privateKey);

		textBoxECCPublicKey->Text = publicKeyPEM;
		textBoxECCPrivateKey->Text = privateKeyPEM;

		richTextBox1->Text = "ECC P-256 key pair generated successfully!\r\n\r\n" +
			"Public Key (PEM): " + publicKeyPEM->Substring(0, Math::Min(100, publicKeyPEM->Length)) + "...\r\n" +
			"Private Key (PEM): " + privateKeyPEM->Substring(0, Math::Min(100, privateKeyPEM->Length)) + "...";
		richTextBox1->ForeColor = Color::DarkGreen;
	}
	catch (Exception^ ex)
	{
		MessageBox::Show("ECC key generation failed: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
	}
}

void MainForm::radioKeyType_CheckedChanged(System::Object^ sender, System::EventArgs^ e)
{
	UpdateKeyInfo();
}

void MainForm::buttonImportPublic_Click(System::Object^ sender, System::EventArgs^ e)
{
	OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
	openFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	openFileDialog->Title = "Import Public Key (PEM)";
	if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			String^ pemContent = File::ReadAllText(openFileDialog->FileName);
			textBoxPublicKey->Text = pemContent;
			MessageBox::Show("Public key imported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to import public key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonImportPrivate_Click(System::Object^ sender, System::EventArgs^ e)
{
	OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
	openFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	openFileDialog->Title = "Import Private Key (PEM)";
	if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			String^ pemContent = File::ReadAllText(openFileDialog->FileName);
			textBoxPrivateKey->Text = pemContent;
			MessageBox::Show("Private key imported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to import private key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonExportPublic_Click(System::Object^ sender, System::EventArgs^ e)
{
	SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
	saveFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	saveFileDialog->Title = "Export Public Key (PEM)";
	saveFileDialog->FileName = "public_key.pem";
	if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			File::WriteAllText(saveFileDialog->FileName, textBoxPublicKey->Text);
			MessageBox::Show("Public key exported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to export public key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonExportPrivate_Click(System::Object^ sender, System::EventArgs^ e)
{
	SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
	saveFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	saveFileDialog->Title = "Export Private Key (PEM)";
	saveFileDialog->FileName = "private_key.pem";
	if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			File::WriteAllText(saveFileDialog->FileName, textBoxPrivateKey->Text);
			MessageBox::Show("Private key exported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to export private key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonImportECCPublic_Click(System::Object^ sender, System::EventArgs^ e)
{
	OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
	openFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	openFileDialog->Title = "Import ECC Public Key (PEM)";
	if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			String^ pemContent = File::ReadAllText(openFileDialog->FileName);
			textBoxECCPublicKey->Text = pemContent;
			MessageBox::Show("ECC Public key imported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to import ECC public key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonImportECCPrivate_Click(System::Object^ sender, System::EventArgs^ e)
{
	OpenFileDialog^ openFileDialog = gcnew OpenFileDialog();
	openFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	openFileDialog->Title = "Import ECC Private Key (PEM)";
	if (openFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			String^ pemContent = File::ReadAllText(openFileDialog->FileName);
			textBoxECCPrivateKey->Text = pemContent;
			MessageBox::Show("ECC Private key imported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to import ECC private key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonExportECCPublic_Click(System::Object^ sender, System::EventArgs^ e)
{
	SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
	saveFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	saveFileDialog->Title = "Export ECC Public Key (PEM)";
	saveFileDialog->FileName = "ecc_public_key.pem";
	if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			File::WriteAllText(saveFileDialog->FileName, textBoxECCPublicKey->Text);
			MessageBox::Show("ECC Public key exported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to export ECC public key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

void MainForm::buttonExportECCPrivate_Click(System::Object^ sender, System::EventArgs^ e)
{
	SaveFileDialog^ saveFileDialog = gcnew SaveFileDialog();
	saveFileDialog->Filter = "PEM files (*.pem)|*.pem|All files (*.*)|*.*";
	saveFileDialog->Title = "Export ECC Private Key (PEM)";
	saveFileDialog->FileName = "ecc_private_key.pem";
	if (saveFileDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		try
		{
			File::WriteAllText(saveFileDialog->FileName, textBoxECCPrivateKey->Text);
			MessageBox::Show("ECC Private key exported successfully!", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
		}
		catch (Exception^ ex)
		{
			MessageBox::Show("Failed to export ECC private key: " + ex->Message, "Error", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
	}
}

// ===== RSA IMPLEMENTATION =====

MainForm::RSAKeyPair^ MainForm::GenerateRSAKeyPair(int keySize)
{
	RSAKeyPair^ keyPair = gcnew RSAKeyPair();

	// Generate two large prime numbers
	keyPair->p = GenerateRandomPrime(keySize / 2);
	keyPair->q = GenerateRandomPrime(keySize / 2);

	// Ensure p and q are not equal
	while (BigInteger::Compare(keyPair->p, keyPair->q) == 0)
	{
		keyPair->q = GenerateRandomPrime(keySize / 2);
	}

	// Compute n = p * q
	keyPair->n = BigInteger::Multiply(keyPair->p, keyPair->q);

	// Compute φ(n) = (p-1)*(q-1)
	BigInteger p_minus_1 = BigInteger::Subtract(keyPair->p, BigInteger::One);
	BigInteger q_minus_1 = BigInteger::Subtract(keyPair->q, BigInteger::One);
	BigInteger phi = BigInteger::Multiply(p_minus_1, q_minus_1);

	// Choose public exponent e (common values: 3, 17, 65537)
	keyPair->e = BigInteger(65537);

	// Ensure e and φ(n) are coprime
	while (BigInteger::GreatestCommonDivisor(keyPair->e, phi) != BigInteger::One)
	{
		keyPair->e = BigInteger::Add(keyPair->e, 2);
	}

	// Compute private exponent d = e^(-1) mod φ(n)
	keyPair->d = ModularInverse(keyPair->e, phi);

	return keyPair;
}

BigInteger MainForm::ModularInverse(BigInteger a, BigInteger m)
{
	BigInteger m0 = m;
	BigInteger y = BigInteger::Zero;
	BigInteger x = BigInteger::One;

	if (BigInteger::Compare(m, BigInteger::One) == 0)
		return BigInteger::Zero;

	while (BigInteger::Compare(a, BigInteger::One) > 0)
	{
		// q is quotient
		BigInteger q = BigInteger::Divide(a, m);
		BigInteger t = m;

		// m is remainder now, process same as Euclid's algo
		m = BigInteger::Remainder(a, m);
		a = t;
		t = y;

		// Update y and x
		y = BigInteger::Subtract(x, BigInteger::Multiply(q, y));
		x = t;
	}

	// Make x positive
	if (BigInteger::Compare(x, BigInteger::Zero) < 0)
		x = BigInteger::Add(x, m0);

	return x;
}

bool MainForm::IsPrime(BigInteger n, int k)
{
	if (BigInteger::Compare(n, BigInteger::One) <= 0) return false;
	if (BigInteger::Compare(n, 3) <= 0) return true;

	// Check if even
	if (BigInteger::Remainder(n, 2).IsZero) return false;

	// Write n-1 as 2^r * d
	BigInteger d = BigInteger::Subtract(n, BigInteger::One);
	int r = 0;
	while (BigInteger::Remainder(d, 2).IsZero)
	{
		d = BigInteger::Divide(d, 2);
		r++;
	}

	// Witness loop
	Random^ rand = gcnew Random();
	for (int i = 0; i < k; i++)
	{
		// Pick a random number a in [2, n-2]
		array<Byte>^ bytes = gcnew array<Byte>(n.ToByteArray()->Length);
		rand->NextBytes(bytes);
		BigInteger a = BigInteger(bytes);

		// Ensure a is positive
		if (a.Sign < 0) a = BigInteger::Negate(a);

		// Ensure a is in range [2, n-2]
		if (BigInteger::Compare(a, 2) < 0)
			a = BigInteger(2);
		if (BigInteger::Compare(a, BigInteger::Subtract(n, 2)) >= 0)
			a = BigInteger::Subtract(n, 3);

		// Compute x = a^d mod n
		BigInteger x = ModularPow(a, d, n);

		if (BigInteger::Compare(x, BigInteger::One) == 0 ||
			BigInteger::Compare(x, BigInteger::Subtract(n, BigInteger::One)) == 0)
			continue;

		bool continueLoop = false;
		for (int j = 0; j < r - 1; j++)
		{
			x = ModularPow(x, 2, n);
			if (BigInteger::Compare(x, BigInteger::Subtract(n, BigInteger::One)) == 0)
			{
				continueLoop = true;
				break;
			}
		}

		if (continueLoop)
			continue;

		return false; // n is composite
	}

	return true; // n is probably prime
}

BigInteger MainForm::GenerateRandomPrime(int bits)
{
	RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();
	int byteCount = (bits + 7) / 8;

	while (true)
	{
		// Generate random bytes
		array<Byte>^ bytes = gcnew array<Byte>(byteCount);
		rng->GetBytes(bytes);

		// Ensure the number is odd and has the right bit length
		bytes[bytes->Length - 1] |= 0x01; // Make odd
		bytes[0] |= 0x80; // Ensure high bit is set for correct bit length

		BigInteger candidate = BigInteger(bytes);

		// Ensure positive
		if (candidate.Sign < 0)
			candidate = BigInteger::Negate(candidate);

		// Simple primality test with fewer rounds for speed
		if (IsPrime(candidate, 3))
			return candidate;
	}
}

// FIXED ModularPow function
BigInteger MainForm::ModularPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
{
	// Handle edge cases
	if (BigInteger::Compare(modulus, BigInteger::One) == 0)
		return BigInteger::Zero;

	if (BigInteger::Compare(exponent, BigInteger::Zero) == 0)
		return BigInteger::One;

	if (BigInteger::Compare(exponent, BigInteger::One) == 0)
		return BigInteger::Remainder(baseValue, modulus);

	BigInteger result = BigInteger::One;
	BigInteger baseVal = BigInteger::Remainder(baseValue, modulus);
	BigInteger exp = exponent;

	while (BigInteger::Compare(exp, BigInteger::Zero) > 0)
	{
		// If exponent is odd (check if LSB is 1)
		array<Byte>^ expBytes = exp.ToByteArray();
		if ((expBytes[0] & 1) == 1)
		{
			result = BigInteger::Remainder(BigInteger::Multiply(result, baseVal), modulus);
		}

		// Square the base
		baseVal = BigInteger::Remainder(BigInteger::Multiply(baseVal, baseVal), modulus);

		// Divide exponent by 2
		exp = BigInteger::Divide(exp, 2);
	}

	return result;
}

array<Byte>^ MainForm::RSA_Encrypt(array<Byte>^ data, BigInteger n, BigInteger e)
{
	try
	{
		// For 2048-bit RSA
		int keySizeBytes = 256;

		// ====== SIMPLE PADDING ======
		// Just add zeros before the message

		// Maximum data size
		int maxDataSize = keySizeBytes - 1; // Leave room

		if (data->Length > maxDataSize)
		{
			throw gcnew ArgumentException(String::Format(
				"Message too long. Maximum is {0} bytes, got {1} bytes.",
				maxDataSize, data->Length));
		}

		// Create padded block with zeros before message
		array<Byte>^ paddedBlock = gcnew array<Byte>(keySizeBytes);
		Array::Clear(paddedBlock, 0, keySizeBytes);

		// Calculate offset (put message at the end)
		int offset = keySizeBytes - data->Length;

		// Copy message to the end
		Array::Copy(data, 0, paddedBlock, offset, data->Length);

		// ====== Convert to BigInteger ======
		array<Byte>^ leBlock = (array<Byte>^)paddedBlock->Clone();
		Array::Reverse(leBlock);

		BigInteger m = BigInteger(leBlock);
		if (m.Sign < 0) m = -m;

		// Check m < n
		if (m >= n)
		{
			// Try with one more zero byte
			offset = keySizeBytes - data->Length - 1;
			Array::Clear(paddedBlock, 0, keySizeBytes);
			Array::Copy(data, 0, paddedBlock, offset, data->Length);

			Array::Reverse(paddedBlock);
			m = BigInteger(paddedBlock);
			if (m.Sign < 0) m = -m;

			if (m >= n)
			{
				throw gcnew ArgumentException("Message too large even with padding");
			}
		}

		// ====== Encrypt ======
		BigInteger c = ModularPow(m, e, n);

		// ====== Convert result to bytes ======
		array<Byte>^ resultBytes = c.ToByteArray();

		// Remove sign byte if present
		if (resultBytes->Length > 0 && resultBytes[resultBytes->Length - 1] == 0)
		{
			array<Byte>^ trimmed = gcnew array<Byte>(resultBytes->Length - 1);
			Array::Copy(resultBytes, 0, trimmed, 0, trimmed->Length);
			resultBytes = trimmed;
		}

		// Reverse to big-endian
		Array::Reverse(resultBytes);

		// ====== Ensure exactly keySizeBytes ======
		array<Byte>^ finalResult = gcnew array<Byte>(keySizeBytes);
		Array::Clear(finalResult, 0, keySizeBytes);

		if (resultBytes->Length <= keySizeBytes)
		{
			int resultOffset = keySizeBytes - resultBytes->Length;
			Array::Copy(resultBytes, 0, finalResult, resultOffset, resultBytes->Length);
		}
		else
		{
			int resultOffset = resultBytes->Length - keySizeBytes;
			Array::Copy(resultBytes, resultOffset, finalResult, 0, keySizeBytes);
		}

		return finalResult;
	}
	catch (Exception^ ex)
	{
		throw gcnew Exception("RSA Encryption failed: " + ex->Message);
	}
}

array<Byte>^ MainForm::RSA_Decrypt(array<Byte>^ cipherBytes, BigInteger n, BigInteger d)
{
	try
	{
		// For 2048-bit RSA
		int keySizeBytes = 256;

		// ====== 1. Prepare ciphertext ======
		array<Byte>^ ciphertext = gcnew array<Byte>(keySizeBytes);
		Array::Clear(ciphertext, 0, keySizeBytes);

		// Always take exactly keySizeBytes
		if (cipherBytes->Length >= keySizeBytes)
		{
			// Take the LAST keySizeBytes
			int offset = cipherBytes->Length - keySizeBytes;
			Array::Copy(cipherBytes, offset, ciphertext, 0, keySizeBytes);
		}
		else
		{
			// Pad with zeros at the beginning
			int offset = keySizeBytes - cipherBytes->Length;
			Array::Copy(cipherBytes, 0, ciphertext, offset, cipherBytes->Length);
		}

		// ====== 2. Convert to BigInteger and decrypt ======
		array<Byte>^ leCiphertext = (array<Byte>^)ciphertext->Clone();
		Array::Reverse(leCiphertext);

		BigInteger c = BigInteger(leCiphertext);
		if (c.Sign < 0) c = -c;

		// Decrypt
		BigInteger m = ModularPow(c, d, n);

		// ====== 3. Convert result to bytes ======
		array<Byte>^ resultBytes = m.ToByteArray();

		// Remove sign byte if present
		if (resultBytes->Length > 0 && resultBytes[resultBytes->Length - 1] == 0)
		{
			array<Byte>^ trimmed = gcnew array<Byte>(resultBytes->Length - 1);
			Array::Copy(resultBytes, 0, trimmed, 0, trimmed->Length);
			resultBytes = trimmed;
		}

		// Reverse to big-endian
		Array::Reverse(resultBytes);

		// ====== 4. Ensure exactly keySizeBytes ======
		array<Byte>^ paddedData = gcnew array<Byte>(keySizeBytes);
		Array::Clear(paddedData, 0, keySizeBytes);

		if (resultBytes->Length <= keySizeBytes)
		{
			int offset = keySizeBytes - resultBytes->Length;
			Array::Copy(resultBytes, 0, paddedData, offset, resultBytes->Length);
		}
		else
		{
			int offset = resultBytes->Length - keySizeBytes;
			Array::Copy(resultBytes, offset, paddedData, 0, keySizeBytes);
		}

		// ====== 5. SIMPLE EXTRACTION - Look for actual message ======

		// Method 1: Try to find the actual data (skip all zeros and padding)
		// Look for where the actual message starts
		for (int i = 0; i < paddedData->Length; i++)
		{
			// Skip zeros and non-printable padding bytes
			if (paddedData[i] == 0 || (paddedData[i] < 32 && paddedData[i] != '\r' && paddedData[i] != '\n' && paddedData[i] != '\t'))
				continue;

			// Check if this could be the start of a UTF8 message
			int remaining = paddedData->Length - i;
			array<Byte>^ testSlice = gcnew array<Byte>(remaining);
			Array::Copy(paddedData, i, testSlice, 0, remaining);

			try
			{
				String^ testString = Encoding::UTF8->GetString(testSlice);

				// Check if it contains mostly printable characters
				int printableCount = 0;
				for each (Char c in testString)
				{
					if (c >= 32 && c <= 126) // Printable ASCII
						printableCount++;
					else if (c == '\r' || c == '\n' || c == '\t') // Common whitespace
						printableCount++;
				}

				// If we have a decent amount of printable characters, return it
				if (printableCount >= testString->Length * 0.7 && testString->Length > 0)
				{
					return testSlice;
				}
			}
			catch (...) {}
		}

		// Method 2: Just return everything after the first non-zero byte
		int firstValid = -1;
		for (int i = 0; i < paddedData->Length; i++)
		{
			if (paddedData[i] != 0)
			{
				firstValid = i;
				break;
			}
		}

		if (firstValid != -1)
		{
			int messageLength = paddedData->Length - firstValid;
			array<Byte>^ message = gcnew array<Byte>(messageLength);
			Array::Copy(paddedData, firstValid, message, 0, messageLength);
			return message;
		}

		// Method 3: Return the raw data
		return paddedData;
	}
	catch (Exception^ ex)
	{
		throw gcnew Exception("RSA Decryption failed: " + ex->Message);
	}
}

// Helper function to check if text looks valid
bool MainForm::IsValidText(String^ text)
{
	if (String::IsNullOrEmpty(text))
		return false;

	// Check for common non-printable characters that shouldn't be in normal text
	for each (Char c in text)
	{
		if (c < 32 && c != '\r' && c != '\n' && c != '\t')
		{
			return false;
		}
	}

	// Check ratio of printable characters
	int printable = 0;
	for each (Char c in text)
	{
		if (c >= 32 && c <= 126)
			printable++;
	}

	return (printable * 1.0 / text->Length) > 0.8; // At least 80% printable
}

// ===== PEM FORMAT SUPPORT =====

array<Byte>^ MainForm::EncodeDERInteger(BigInteger value)
{
	array<Byte>^ bytes = value.ToByteArray();

	// Remove leading zero if it exists and the next byte has high bit set
	if (bytes->Length > 1 && bytes[0] == 0 && (bytes[1] & 0x80) != 0)
	{
		array<Byte>^ trimmed = gcnew array<Byte>(bytes->Length - 1);
		Array::Copy(bytes, 1, trimmed, 0, trimmed->Length);
		bytes = trimmed;
	}

	List<Byte>^ result = gcnew List<Byte>();

	// INTEGER tag
	result->Add(0x02);

	// Length (variable-length encoding)
	if (bytes->Length < 128)
	{
		result->Add((Byte)bytes->Length);
	}
	else
	{
		int len = bytes->Length;
		List<Byte>^ lenBytes = gcnew List<Byte>();
		while (len > 0)
		{
			lenBytes->Insert(0, (Byte)(len & 0xFF));
			len >>= 8;
		}
		result->Add((Byte)(0x80 | lenBytes->Count));
		for each (Byte b in lenBytes)
		{
			result->Add(b);
		}
	}

	// Value
	for each (Byte b in bytes)
	{
		result->Add(b);
	}

	return result->ToArray();
}

array<Byte>^ MainForm::EncodeDERSequence(List<array<Byte>^>^ elements)
{
	List<Byte>^ content = gcnew List<Byte>();

	for each (array<Byte> ^ element in elements)
	{
		for each (Byte b in element)
		{
			content->Add(b);
		}
	}

	List<Byte>^ result = gcnew List<Byte>();

	// SEQUENCE tag
	result->Add(0x30);

	// Length (variable-length encoding)
	if (content->Count < 128)
	{
		result->Add((Byte)content->Count);
	}
	else
	{
		int len = content->Count;
		List<Byte>^ lenBytes = gcnew List<Byte>();
		while (len > 0)
		{
			lenBytes->Insert(0, (Byte)(len & 0xFF));
			len >>= 8;
		}
		result->Add((Byte)(0x80 | lenBytes->Count));
		for each (Byte b in lenBytes)
		{
			result->Add(b);
		}
	}

	// Content
	for each (Byte b in content)
	{
		result->Add(b);
	}

	return result->ToArray();
}

BigInteger MainForm::DecodeDERInteger(array<Byte>^ der)
{
	int index = 0;

	// Check tag
	if (der[index++] != 0x02)
		throw gcnew ArgumentException("Not an INTEGER tag");

	// Read length
	int length = der[index++];
	if ((length & 0x80) != 0)
	{
		int lenBytes = length & 0x7F;
		length = 0;
		for (int i = 0; i < lenBytes; i++)
		{
			length = (length << 8) | der[index++];
		}
	}

	// Read value
	array<Byte>^ value = gcnew array<Byte>(length);
	Array::Copy(der, index, value, 0, length);

	// Add leading zero if high bit is set
	if (value->Length > 0 && (value[0] & 0x80) != 0)
	{
		array<Byte>^ extended = gcnew array<Byte>(value->Length + 1);
		extended[0] = 0;
		Array::Copy(value, 0, extended, 1, value->Length);
		value = extended;
	}

	return BigInteger(value);
}

List<array<Byte>^>^ MainForm::ParseDERSequence(array<Byte>^ der)
{
	List<array<Byte>^>^ elements = gcnew List<array<Byte>^>();
	int index = 0;

	// Check tag
	if (der[index++] != 0x30)
		throw gcnew ArgumentException("Not a SEQUENCE tag");

	// Read length
	int length = der[index++];
	if ((length & 0x80) != 0)
	{
		int lenBytes = length & 0x7F;
		length = 0;
		for (int i = 0; i < lenBytes; i++)
		{
			length = (length << 8) | der[index++];
		}
	}

	int endIndex = index + length;

	while (index < endIndex)
	{
		int start = index;
		Byte tag = der[index++];

		// Read element length
		int elemLength = der[index++];
		if ((elemLength & 0x80) != 0)
		{
			int lenBytes = elemLength & 0x7F;
			elemLength = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				elemLength = (elemLength << 8) | der[index++];
			}
		}

		// Skip to next element
		index += elemLength;

		array<Byte>^ element = gcnew array<Byte>(index - start);
		Array::Copy(der, start, element, 0, element->Length);
		elements->Add(element);
	}

	return elements;
}

String^ MainForm::EncodePEM(String^ label, array<Byte>^ data)
{
	String^ base64 = Convert::ToBase64String(data);
	StringBuilder^ pem = gcnew StringBuilder();

	pem->AppendLine("-----BEGIN " + label + "-----");

	// Split base64 into lines of 64 characters
	for (int i = 0; i < base64->Length; i += 64)
	{
		int length = Math::Min(64, base64->Length - i);
		pem->AppendLine(base64->Substring(i, length));
	}

	pem->AppendLine("-----END " + label + "-----");

	return pem->ToString();
}

array<Byte>^ MainForm::DecodePEM(String^ pem)
{
	// Remove header and footer
	array<String^>^ lines = pem->Split(gcnew array<String^>{ "\r\n", "\r", "\n" }, StringSplitOptions::None);
	List<String^>^ base64Lines = gcnew List<String^>();

	bool inBody = false;
	for each (String ^ line in lines)
	{
		if (line->StartsWith("-----BEGIN"))
		{
			inBody = true;
			continue;
		}
		if (line->StartsWith("-----END"))
		{
			break;
		}
		if (inBody && !String::IsNullOrEmpty(line))
		{
			base64Lines->Add(line);
		}
	}

	String^ base64 = String::Join("", base64Lines->ToArray());
	return Convert::FromBase64String(base64);
}

String^ MainForm::ExportPublicKeyToPEM(BigInteger n, BigInteger e)
{
	List<array<Byte>^>^ elements = gcnew List<array<Byte>^>();
	elements->Add(EncodeDERInteger(n));
	elements->Add(EncodeDERInteger(e));

	array<Byte>^ publicKeyInfo = EncodeDERSequence(elements);
	return EncodePEM("RSA PUBLIC KEY", publicKeyInfo);
}

String^ MainForm::ExportPrivateKeyToPEM(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q)
{
	List<array<Byte>^>^ elements = gcnew List<array<Byte>^>();

	// Version (0 for RSA)
	elements->Add(EncodeDERInteger(BigInteger::Zero));

	// n
	elements->Add(EncodeDERInteger(n));

	// e
	elements->Add(EncodeDERInteger(e));

	// d
	elements->Add(EncodeDERInteger(d));

	// p
	elements->Add(EncodeDERInteger(p));

	// q
	elements->Add(EncodeDERInteger(q));

	// dp = d mod (p-1)
	BigInteger p_minus_1 = BigInteger::Subtract(p, BigInteger::One);
	BigInteger dp = BigInteger::Remainder(d, p_minus_1);
	elements->Add(EncodeDERInteger(dp));

	// dq = d mod (q-1)
	BigInteger q_minus_1 = BigInteger::Subtract(q, BigInteger::One);
	BigInteger dq = BigInteger::Remainder(d, q_minus_1);
	elements->Add(EncodeDERInteger(dq));

	// qinv = q^(-1) mod p
	BigInteger qinv = ModularInverse(q, p);
	elements->Add(EncodeDERInteger(qinv));

	array<Byte>^ privateKeyInfo = EncodeDERSequence(elements);
	return EncodePEM("RSA PRIVATE KEY", privateKeyInfo);
}

bool MainForm::ParsePublicKeyDER(array<Byte>^ der, BigInteger% n, BigInteger% e)
{
	try
	{
		int index = 0;

		// Check SEQUENCE tag
		if (der[index++] != 0x30)
			return false;

		// Read sequence length
		int seqLen = der[index++];
		if (seqLen & 0x80)
		{
			int lenBytes = seqLen & 0x7F;
			seqLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				seqLen = (seqLen << 8) | der[index++];
			}
		}

		// Try PKCS#1 format (RSAPublicKey)
		if (der[index] == 0x30)
		{
			// This is PKCS#1 format
			index++; // Skip SEQUENCE
			int pkcs1Len = der[index++];
			if (pkcs1Len & 0x80)
			{
				int lenBytes = pkcs1Len & 0x7F;
				pkcs1Len = 0;
				for (int i = 0; i < lenBytes; i++)
				{
					pkcs1Len = (pkcs1Len << 8) | der[index++];
				}
			}
		}

		// Check INTEGER tag for n
		if (der[index++] != 0x02)
			return false;

		// Read n length
		int nLen = der[index++];
		if (nLen & 0x80)
		{
			int lenBytes = nLen & 0x7F;
			nLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				nLen = (nLen << 8) | der[index++];
			}
		}

		// Read n value
		array<Byte>^ nBytes = gcnew array<Byte>(nLen);
		Array::Copy(der, index, nBytes, 0, nLen);
		index += nLen;

		// Convert to BigInteger
		n = BigInteger(nBytes);
		if (n.Sign < 0) n = -n;

		// Check INTEGER tag for e
		if (der[index++] != 0x02)
			return false;

		// Read e length
		int eLen = der[index++];
		if (eLen & 0x80)
		{
			int lenBytes = eLen & 0x7F;
			eLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				eLen = (eLen << 8) | der[index++];
			}
		}

		// Read e value
		array<Byte>^ eBytes = gcnew array<Byte>(eLen);
		Array::Copy(der, index, eBytes, 0, eLen);

		// Convert to BigInteger
		e = BigInteger(eBytes);
		if (e.Sign < 0) e = -e;

		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool MainForm::ParsePrivateKeyDER(array<Byte>^ der, BigInteger% n, BigInteger% e, BigInteger% d, BigInteger% p, BigInteger% q)
{
	try
	{
		int index = 0;

		// Check SEQUENCE tag
		if (der[index++] != 0x30)
			return false;

		// Read sequence length
		int seqLen = der[index++];
		if (seqLen & 0x80)
		{
			int lenBytes = seqLen & 0x7F;
			seqLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				seqLen = (seqLen << 8) | der[index++];
			}
		}

		// Skip version (should be 0)
		if (der[index++] != 0x02)
			return false;

		int versionLen = der[index++];
		index += versionLen;

		// Read n
		if (der[index++] != 0x02)
			return false;

		int nLen = der[index++];
		if (nLen & 0x80)
		{
			int lenBytes = nLen & 0x7F;
			nLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				nLen = (nLen << 8) | der[index++];
			}
		}

		array<Byte>^ nBytes = gcnew array<Byte>(nLen);
		Array::Copy(der, index, nBytes, 0, nLen);
		index += nLen;
		n = BigInteger(nBytes);
		if (n.Sign < 0) n = -n;

		// Read e
		if (der[index++] != 0x02)
			return false;

		int eLen = der[index++];
		if (eLen & 0x80)
		{
			int lenBytes = eLen & 0x7F;
			eLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				eLen = (eLen << 8) | der[index++];
			}
		}

		array<Byte>^ eBytes = gcnew array<Byte>(eLen);
		Array::Copy(der, index, eBytes, 0, eLen);
		index += eLen;
		e = BigInteger(eBytes);
		if (e.Sign < 0) e = -e;

		// Read d
		if (der[index++] != 0x02)
			return false;

		int dLen = der[index++];
		if (dLen & 0x80)
		{
			int lenBytes = dLen & 0x7F;
			dLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				dLen = (dLen << 8) | der[index++];
			}
		}

		array<Byte>^ dBytes = gcnew array<Byte>(dLen);
		Array::Copy(der, index, dBytes, 0, dLen);
		index += dLen;
		d = BigInteger(dBytes);
		if (d.Sign < 0) d = -d;

		// Read p
		if (der[index++] != 0x02)
			return false;

		int pLen = der[index++];
		if (pLen & 0x80)
		{
			int lenBytes = pLen & 0x7F;
			pLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				pLen = (pLen << 8) | der[index++];
			}
		}

		array<Byte>^ pBytes = gcnew array<Byte>(pLen);
		Array::Copy(der, index, pBytes, 0, pLen);
		index += pLen;
		p = BigInteger(pBytes);
		if (p.Sign < 0) p = -p;

		// Read q
		if (der[index++] != 0x02)
			return false;

		int qLen = der[index++];
		if (qLen & 0x80)
		{
			int lenBytes = qLen & 0x7F;
			qLen = 0;
			for (int i = 0; i < lenBytes; i++)
			{
				qLen = (qLen << 8) | der[index++];
			}
		}

		array<Byte>^ qBytes = gcnew array<Byte>(qLen);
		Array::Copy(der, index, qBytes, 0, qLen);
		index += qLen;
		q = BigInteger(qBytes);
		if (q.Sign < 0) q = -q;

		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool MainForm::ImportPublicKeyFromPEM(String^ pem, BigInteger% n, BigInteger% e)
{
	try
	{
		// Clean up the PEM string
		pem = pem->Trim();

		// Remove headers and footers
		if (pem->Contains("-----BEGIN"))
		{
			// Extract base64 content
			array<String^>^ lines = pem->Split(gcnew array<String^>{ "\r\n", "\r", "\n" }, StringSplitOptions::None);
			StringBuilder^ base64Content = gcnew StringBuilder();

			bool inBody = false;
			for each (String ^ line in lines)
			{
				if (line->StartsWith("-----BEGIN PUBLIC KEY-----") ||
					line->StartsWith("-----BEGIN RSA PUBLIC KEY-----"))
				{
					inBody = true;
					continue;
				}
				if (line->StartsWith("-----END"))
				{
					break;
				}
				if (inBody)
				{
					base64Content->Append(line->Trim());
				}
			}

			array<Byte>^ derBytes = Convert::FromBase64String(base64Content->ToString());
			return ParsePublicKeyDER(derBytes, n, e);
		}
		else
		{
			// Try to parse as raw base64
			try
			{
				array<Byte>^ derBytes = Convert::FromBase64String(pem);
				return ParsePublicKeyDER(derBytes, n, e);
			}
			catch (...)
			{
				return false;
			}
		}
	}
	catch (...)
	{
		return false;
	}
}

bool MainForm::ImportPrivateKeyFromPEM(String^ pem, BigInteger% n, BigInteger% e, BigInteger% d, BigInteger% p, BigInteger% q)
{
	try
	{
		// Clean up the PEM string
		pem = pem->Trim();

		// Remove headers and footers
		if (pem->Contains("-----BEGIN"))
		{
			// Extract base64 content
			array<String^>^ lines = pem->Split(gcnew array<String^>{ "\r\n", "\r", "\n" }, StringSplitOptions::None);
			StringBuilder^ base64Content = gcnew StringBuilder();

			bool inBody = false;
			for each (String ^ line in lines)
			{
				if (line->StartsWith("-----BEGIN PRIVATE KEY-----") ||
					line->StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
				{
					inBody = true;
					continue;
				}
				if (line->StartsWith("-----END"))
				{
					break;
				}
				if (inBody)
				{
					base64Content->Append(line->Trim());
				}
			}

			array<Byte>^ derBytes = Convert::FromBase64String(base64Content->ToString());
			return ParsePrivateKeyDER(derBytes, n, e, d, p, q);
		}
		else
		{
			// Try to parse as raw base64
			try
			{
				array<Byte>^ derBytes = Convert::FromBase64String(pem);
				return ParsePrivateKeyDER(derBytes, n, e, d, p, q);
			}
			catch (...)
			{
				return false;
			}
		}
	}
	catch (...)
	{
		return false;
	}
}

// ===== ECC P-256 IMPLEMENTATION =====

void MainForm::InitializeECC_P256()
{
	// NIST P-256 (secp256r1) curve parameters
	// Prime modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1
	array<Byte>^ p_bytes = {
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};
	p = BigInteger(p_bytes);

	// Curve parameter a = p - 3
	a = BigInteger::Subtract(p, 3);

	// Curve parameter b
	array<Byte>^ b_bytes = {
		0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
		0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
		0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
		0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
	};
	b = BigInteger(b_bytes);

	// Order of the base point n
	array<Byte>^ n_bytes = {
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
		0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
	};
	n = BigInteger(n_bytes);

	// Base point G
	array<Byte>^ Gx_bytes = {
		0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
		0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
		0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
		0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
	};
	array<Byte>^ Gy_bytes = {
		0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
		0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
		0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
		0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
	};

	BigInteger Gx = BigInteger(Gx_bytes);
	BigInteger Gy = BigInteger(Gy_bytes);
	G = gcnew ECCPoint(Gx, Gy);
}

BigInteger MainForm::GenerateRandomPrivateKey()
{
	RNGCryptoServiceProvider^ rng = gcnew RNGCryptoServiceProvider();

	// Generate random private key in range [1, n-1]
	while (true)
	{
		array<Byte>^ bytes = gcnew array<Byte>(32);
		rng->GetBytes(bytes);

		// Ensure it's within the valid range
		BigInteger d = BigInteger(bytes);
		if (d.Sign < 0) d = -d;

		// Make sure d is in [1, n-1]
		if (d > BigInteger::Zero && d < n)
			return d;
	}
}

MainForm::ECCKeyPair^ MainForm::GenerateECCKeyPair()
{
	ECCKeyPair^ keyPair = gcnew ECCKeyPair();

	// Generate random private key
	keyPair->privateKey = GenerateRandomPrivateKey();

	// Compute public key: Q = d * G
	keyPair->publicKey = ECC_ScalarMultiply(keyPair->privateKey, G);

	return keyPair;
}

// Modular arithmetic functions for ECC
BigInteger MainForm::ECC_Mod(BigInteger value)
{
	BigInteger result = BigInteger::Remainder(value, p);
	if (result.Sign < 0)
		result = BigInteger::Add(result, p);
	return result;
}

BigInteger MainForm::ECC_ModAdd(BigInteger a, BigInteger b)
{
	return ECC_Mod(BigInteger::Add(a, b));
}

BigInteger MainForm::ECC_ModSub(BigInteger a, BigInteger b)
{
	return ECC_Mod(BigInteger::Subtract(a, b));
}

BigInteger MainForm::ECC_ModMul(BigInteger a, BigInteger b)
{
	return ECC_Mod(BigInteger::Multiply(a, b));
}

BigInteger MainForm::ECC_ModSquare(BigInteger a)
{
	return ECC_ModMul(a, a);
}

BigInteger MainForm::ECC_ModInverse(BigInteger a)
{
	// Using Fermat's Little Theorem: a^(p-2) mod p
	if (BigInteger::Compare(a, BigInteger::Zero) == 0)
		throw gcnew ArgumentException("Cannot compute inverse of zero");

	BigInteger exponent = BigInteger::Subtract(p, 2);
	return ModularPow(a, exponent, p);
}

// Point addition: P + Q
MainForm::ECCPoint^ MainForm::ECC_PointAdd(ECCPoint^ P, ECCPoint^ Q)
{
	if (P->isInfinity) return Q;
	if (Q->isInfinity) return P;

	// Check if points are equal (point doubling case)
	if (P->x == Q->x && P->y == Q->y)
		return ECC_PointDouble(P);

	// Check if points are inverses
	BigInteger sumY = ECC_ModAdd(P->y, Q->y);
	if (P->x == Q->x && sumY == BigInteger::Zero)
		return gcnew ECCPoint(); // Return infinity point

	// Compute lambda = (Qy - Py) * (Qx - Px)^(-1) mod p
	BigInteger numerator = ECC_ModSub(Q->y, P->y);
	BigInteger denominator = ECC_ModSub(Q->x, P->x);
	BigInteger lambda = ECC_ModMul(numerator, ECC_ModInverse(denominator));

	// Compute Rx = lambda^2 - Px - Qx mod p
	BigInteger Rx = ECC_ModSub(ECC_ModSub(ECC_ModSquare(lambda), P->x), Q->x);

	// Compute Ry = lambda * (Px - Rx) - Py mod p
	BigInteger Ry = ECC_ModSub(ECC_ModMul(lambda, ECC_ModSub(P->x, Rx)), P->y);

	return gcnew ECCPoint(Rx, Ry);
}

// Point doubling: 2*P
MainForm::ECCPoint^ MainForm::ECC_PointDouble(ECCPoint^ P)
{
	if (P->isInfinity || P->y == BigInteger::Zero)
		return gcnew ECCPoint(); // Return infinity point

	// Compute lambda = (3 * Px^2 + a) * (2 * Py)^(-1) mod p
	BigInteger numerator = ECC_ModAdd(ECC_ModMul(BigInteger(3), ECC_ModSquare(P->x)), a);
	BigInteger denominator = ECC_ModMul(BigInteger(2), P->y);
	BigInteger lambda = ECC_ModMul(numerator, ECC_ModInverse(denominator));

	// Compute Rx = lambda^2 - 2 * Px mod p
	BigInteger Rx = ECC_ModSub(ECC_ModSquare(lambda), ECC_ModMul(BigInteger(2), P->x));

	// Compute Ry = lambda * (Px - Rx) - Py mod p
	BigInteger Ry = ECC_ModSub(ECC_ModMul(lambda, ECC_ModSub(P->x, Rx)), P->y);

	return gcnew ECCPoint(Rx, Ry);
}

// Scalar multiplication: k * P using double-and-add algorithm
MainForm::ECCPoint^ MainForm::ECC_ScalarMultiply(BigInteger k, ECCPoint^ P)
{
	if (k == BigInteger::Zero || P->isInfinity)
		return gcnew ECCPoint(); // Return infinity point

	ECCPoint^ result = gcnew ECCPoint(); // Start with infinity point
	ECCPoint^ current = P;

	// Convert k to byte array to check bits
	array<Byte>^ kBytes = k.ToByteArray();
	BigInteger tempK = k;

	while (tempK > BigInteger::Zero)
	{
		// Check if least significant bit is 1
		// Get the byte array of the current k value
		array<Byte>^ currentBytes = tempK.ToByteArray();

		// Check if LSB (first byte) is odd
		if (currentBytes->Length > 0 && (currentBytes[0] & 1) == 1)
		{
			result = ECC_PointAdd(result, current);
		}

		current = ECC_PointDouble(current);
		tempK = tempK >> 1; // Divide by 2
	}

	return result;
}

bool MainForm::ECC_PointOnCurve(ECCPoint^ P)
{
	if (P->isInfinity) return true;

	// Check y^2 ≡ x^3 + a*x + b (mod p)
	BigInteger left = ECC_ModSquare(P->y);
	BigInteger x3 = ECC_ModMul(ECC_ModSquare(P->x), P->x); // x^3
	BigInteger ax = ECC_ModMul(a, P->x); // a*x
	BigInteger x3_plus_ax = ECC_ModAdd(x3, ax); // x^3 + a*x
	BigInteger right = ECC_ModAdd(x3_plus_ax, b); // x^3 + a*x + b

	return left == right;
}

// ECC Encryption (Simple ECIES-like approach)
array<Byte>^ MainForm::ECC_Encrypt(array<Byte>^ data, ECCPoint^ publicKey)
{
	try
	{
		// Generate ephemeral private key
		BigInteger k = GenerateRandomPrivateKey();

		// Compute shared secret: S = k * publicKey
		ECCPoint^ S = ECC_ScalarMultiply(k, publicKey);

		// Compute ephemeral public key: R = k * G
		ECCPoint^ R = ECC_ScalarMultiply(k, G);

		// Derive encryption key from shared secret x-coordinate
		array<Byte>^ Sx_bytes = S->x.ToByteArray();
		array<Byte>^ key = gcnew array<Byte>(32);

		// Use first 32 bytes of SHA256(Sx) as key
		SHA256^ sha256 = SHA256::Create();
		array<Byte>^ hash = sha256->ComputeHash(Sx_bytes);
		Array::Copy(hash, key, Math::Min(32, hash->Length));

		// Encrypt data with simple XOR (for demonstration)
		// In production, use a proper symmetric cipher like AES
		array<Byte>^ encryptedData = gcnew array<Byte>(data->Length);
		for (int i = 0; i < data->Length; i++)
		{
			encryptedData[i] = (Byte)(data[i] ^ key[i % key->Length]);
		}

		// Combine ephemeral public key and encrypted data
		// Format: R.x || R.y || encryptedData
		array<Byte>^ Rx_bytes = R->x.ToByteArray();
		array<Byte>^ Ry_bytes = R->y.ToByteArray();

		// Ensure Rx and Ry are exactly 32 bytes
		array<Byte>^ Rx_padded = gcnew array<Byte>(32);
		array<Byte>^ Ry_padded = gcnew array<Byte>(32);

		if (Rx_bytes->Length <= 32)
		{
			int offset = 32 - Rx_bytes->Length;
			Array::Copy(Rx_bytes, 0, Rx_padded, offset, Rx_bytes->Length);
		}
		else
		{
			Array::Copy(Rx_bytes, Rx_bytes->Length - 32, Rx_padded, 0, 32);
		}

		if (Ry_bytes->Length <= 32)
		{
			int offset = 32 - Ry_bytes->Length;
			Array::Copy(Ry_bytes, 0, Ry_padded, offset, Ry_bytes->Length);
		}
		else
		{
			Array::Copy(Ry_bytes, Ry_bytes->Length - 32, Ry_padded, 0, 32);
		}

		// Combine everything
		array<Byte>^ result = gcnew array<Byte>(64 + encryptedData->Length);
		Array::Copy(Rx_padded, 0, result, 0, 32);
		Array::Copy(Ry_padded, 0, result, 32, 32);
		Array::Copy(encryptedData, 0, result, 64, encryptedData->Length);

		return result;
	}
	catch (Exception^ ex)
	{
		throw gcnew Exception("ECC Encryption failed: " + ex->Message);
	}
}

// ECC Decryption
array<Byte>^ MainForm::ECC_Decrypt(array<Byte>^ data, BigInteger privateKey)
{
	try
	{
		if (data->Length < 64)
			throw gcnew ArgumentException("Invalid ciphertext length");

		// Extract ephemeral public key R
		array<Byte>^ Rx_bytes = gcnew array<Byte>(32);
		array<Byte>^ Ry_bytes = gcnew array<Byte>(32);
		Array::Copy(data, 0, Rx_bytes, 0, 32);
		Array::Copy(data, 32, Ry_bytes, 0, 32);

		BigInteger Rx = BigInteger(Rx_bytes);
		BigInteger Ry = BigInteger(Ry_bytes);
		ECCPoint^ R = gcnew ECCPoint(Rx, Ry);

		// Extract encrypted data
		array<Byte>^ encryptedData = gcnew array<Byte>(data->Length - 64);
		Array::Copy(data, 64, encryptedData, 0, encryptedData->Length);

		// Compute shared secret: S = privateKey * R
		ECCPoint^ S = ECC_ScalarMultiply(privateKey, R);

		// Derive decryption key from shared secret x-coordinate
		array<Byte>^ Sx_bytes = S->x.ToByteArray();
		array<Byte>^ key = gcnew array<Byte>(32);

		// Use first 32 bytes of SHA256(Sx) as key
		SHA256^ sha256 = SHA256::Create();
		array<Byte>^ hash = sha256->ComputeHash(Sx_bytes);
		Array::Copy(hash, key, Math::Min(32, hash->Length));

		// Decrypt data
		array<Byte>^ decryptedData = gcnew array<Byte>(encryptedData->Length);
		for (int i = 0; i < encryptedData->Length; i++)
		{
			decryptedData[i] = (Byte)(encryptedData[i] ^ key[i % key->Length]);
		}

		return decryptedData;
	}
	catch (Exception^ ex)
	{
		throw gcnew Exception("ECC Decryption failed: " + ex->Message);
	}
}

// ECC PEM Format Support
String^ MainForm::ExportECCPublicKeyToPEM(ECCPoint^ publicKey)
{
	// Simple format: Base64(x || y)
	String^ keyData = ECCPointToBase64(publicKey);
	return EncodePEM("ECC PUBLIC KEY", Encoding::UTF8->GetBytes(keyData));
}

String^ MainForm::ExportECCPrivateKeyToPEM(BigInteger privateKey)
{
	// Simple format: Base64(privateKey)
	String^ keyData = BigIntegerToBase64(privateKey);
	return EncodePEM("ECC PRIVATE KEY", Encoding::UTF8->GetBytes(keyData));
}

bool MainForm::ImportECCPublicKeyFromPEM(String^ pem, ECCPoint^% publicKey)
{
	try
	{
		array<Byte>^ data = DecodePEM(pem);
		String^ keyData = Encoding::UTF8->GetString(data);
		publicKey = Base64ToECCPoint(keyData);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool MainForm::ImportECCPrivateKeyFromPEM(String^ pem, BigInteger% privateKey)
{
	try
	{
		array<Byte>^ data = DecodePEM(pem);
		String^ keyData = Encoding::UTF8->GetString(data);
		privateKey = Base64ToBigInteger(keyData);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

// Helper functions for Base64 encoding/decoding
String^ MainForm::ECCPointToBase64(ECCPoint^ point)
{
	// Format: Base64(x || y)
	array<Byte>^ x_bytes = point->x.ToByteArray();
	array<Byte>^ y_bytes = point->y.ToByteArray();

	// Pad to 32 bytes each
	array<Byte>^ x_padded = gcnew array<Byte>(32);
	array<Byte>^ y_padded = gcnew array<Byte>(32);

	if (x_bytes->Length <= 32)
	{
		int offset = 32 - x_bytes->Length;
		Array::Copy(x_bytes, 0, x_padded, offset, x_bytes->Length);
	}
	else
	{
		Array::Copy(x_bytes, x_bytes->Length - 32, x_padded, 0, 32);
	}

	if (y_bytes->Length <= 32)
	{
		int offset = 32 - y_bytes->Length;
		Array::Copy(y_bytes, 0, y_padded, offset, y_bytes->Length);
	}
	else
	{
		Array::Copy(y_bytes, y_bytes->Length - 32, y_padded, 0, 32);
	}

	array<Byte>^ combined = gcnew array<Byte>(64);
	Array::Copy(x_padded, 0, combined, 0, 32);
	Array::Copy(y_padded, 0, combined, 32, 32);

	return Convert::ToBase64String(combined);
}

MainForm::ECCPoint^ MainForm::Base64ToECCPoint(String^ base64)
{
	array<Byte>^ combined = Convert::FromBase64String(base64);
	if (combined->Length != 64)
		throw gcnew ArgumentException("Invalid ECC point data");

	array<Byte>^ x_bytes = gcnew array<Byte>(32);
	array<Byte>^ y_bytes = gcnew array<Byte>(32);

	Array::Copy(combined, 0, x_bytes, 0, 32);
	Array::Copy(combined, 32, y_bytes, 0, 32);

	BigInteger x = BigInteger(x_bytes);
	BigInteger y = BigInteger(y_bytes);

	return gcnew ECCPoint(x, y);
}

BigInteger MainForm::Base64ToBigInteger(String^ base64)
{
	array<Byte>^ bytes = Convert::FromBase64String(base64);
	return BigInteger(bytes);
}

String^ MainForm::BigIntegerToBase64(BigInteger value)
{
	array<Byte>^ bytes = value.ToByteArray();
	return Convert::ToBase64String(bytes);
}

// ===== ENCRYPTION METHODS =====

String^ MainForm::EncryptString(String^ plainText, String^ algorithm)
{
	array<Byte>^ plainBytes = Encoding::UTF8->GetBytes(plainText);
	array<Byte>^ keyBytes = GetKeyBytesFromInput();
	array<Byte>^ encryptedBytes;

	if (algorithm == "AES")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		encryptedBytes = AES_Encrypt(plainBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "RC4")
	{
		encryptedBytes = RC4_Encrypt(plainBytes, keyBytes);
	}
	else if (algorithm == "ChaCha20")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		array<Byte>^ nonce = gcnew array<Byte>(12);
		Array::Copy(ivBytes, nonce, 12);
		encryptedBytes = ChaCha20_Encrypt(plainBytes, keyBytes, nonce);
	}
	else if (algorithm == "3DES")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		encryptedBytes = TripleDES_Encrypt(plainBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "Blowfish")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		encryptedBytes = Blowfish_Encrypt(plainBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "ECC-256")
	{
		// ECC encryption - requires public key
		String^ publicKeyText = textBoxECCPublicKey->Text;
		if (String::IsNullOrEmpty(publicKeyText))
		{
			throw gcnew ArgumentException("ECC public key is required for encryption");
		}

		ECCPoint^ publicKey;
		if (!ImportECCPublicKeyFromPEM(publicKeyText, publicKey))
		{
			throw gcnew ArgumentException("Invalid ECC public key");
		}

		encryptedBytes = ECC_Encrypt(plainBytes, publicKey);
	}
	else
	{
		throw gcnew ArgumentException("Unsupported algorithm: " + algorithm);
	}

	return Convert::ToBase64String(encryptedBytes);
}

String^ MainForm::DecryptString(String^ cipherText, String^ algorithm)
{
	array<Byte>^ cipherBytes = Convert::FromBase64String(cipherText);
	array<Byte>^ keyBytes = GetKeyBytesFromInput();
	array<Byte>^ decryptedBytes;

	if (algorithm == "AES")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		decryptedBytes = AES_Decrypt(cipherBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "RC4")
	{
		decryptedBytes = RC4_Decrypt(cipherBytes, keyBytes);
	}
	else if (algorithm == "ChaCha20")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		array<Byte>^ nonce = gcnew array<Byte>(12);
		Array::Copy(ivBytes, nonce, 12);
		decryptedBytes = ChaCha20_Decrypt(cipherBytes, keyBytes, nonce);
	}
	else if (algorithm == "3DES")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		decryptedBytes = TripleDES_Decrypt(cipherBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "Blowfish")
	{
		array<Byte>^ ivBytes = Convert::FromBase64String(iv);
		decryptedBytes = Blowfish_Decrypt(cipherBytes, keyBytes, ivBytes);
	}
	else if (algorithm == "ECC-256")
	{
		// ECC decryption - requires private key
		String^ privateKeyText = textBoxECCPrivateKey->Text;
		if (String::IsNullOrEmpty(privateKeyText))
		{
			throw gcnew ArgumentException("ECC private key is required for decryption");
		}

		BigInteger privateKey;
		if (!ImportECCPrivateKeyFromPEM(privateKeyText, privateKey))
		{
			throw gcnew ArgumentException("Invalid ECC private key");
		}

		decryptedBytes = ECC_Decrypt(cipherBytes, privateKey);
	}
	else
	{
		throw gcnew ArgumentException("Unsupported algorithm: " + algorithm);
	}

	return Encoding::UTF8->GetString(decryptedBytes);
}

bool MainForm::EncryptFile(String^ inputFile, String^ outputFile, String^ algorithm)
{
	try
	{
		array<Byte>^ fileData = File::ReadAllBytes(inputFile);
		array<Byte>^ keyBytes = GetKeyBytesFromInput();
		array<Byte>^ encryptedData;

		if (algorithm == "AES")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			encryptedData = AES_Encrypt(fileData, keyBytes, ivBytes);
		}
		else if (algorithm == "RC4")
		{
			encryptedData = RC4_Encrypt(fileData, keyBytes);
		}
		else if (algorithm == "ChaCha20")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			array<Byte>^ nonce = gcnew array<Byte>(12);
			Array::Copy(ivBytes, nonce, 12);
			encryptedData = ChaCha20_Encrypt(fileData, keyBytes, nonce);
		}
		else if (algorithm == "3DES")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			encryptedData = TripleDES_Encrypt(fileData, keyBytes, ivBytes);
		}
		else if (algorithm == "Blowfish")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			encryptedData = Blowfish_Encrypt(fileData, keyBytes, ivBytes);
		}
		else
		{
			return false;
		}

		File::WriteAllBytes(outputFile, encryptedData);
		return true;
	}
	catch (Exception^)
	{
		return false;
	}
}

bool MainForm::DecryptFile(String^ inputFile, String^ outputFile, String^ algorithm)
{
	try
	{
		array<Byte>^ fileData = File::ReadAllBytes(inputFile);
		array<Byte>^ keyBytes = GetKeyBytesFromInput();
		array<Byte>^ decryptedData;

		if (algorithm == "AES")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			decryptedData = AES_Decrypt(fileData, keyBytes, ivBytes);
		}
		else if (algorithm == "RC4")
		{
			decryptedData = RC4_Decrypt(fileData, keyBytes);
		}
		else if (algorithm == "ChaCha20")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			array<Byte>^ nonce = gcnew array<Byte>(12);
			Array::Copy(ivBytes, nonce, 12);
			decryptedData = ChaCha20_Decrypt(fileData, keyBytes, nonce);
		}
		else if (algorithm == "3DES")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			decryptedData = TripleDES_Decrypt(fileData, keyBytes, ivBytes);
		}
		else if (algorithm == "Blowfish")
		{
			array<Byte>^ ivBytes = Convert::FromBase64String(iv);
			decryptedData = Blowfish_Decrypt(fileData, keyBytes, ivBytes);
		}
		else
		{
			return false;
		}

		File::WriteAllBytes(outputFile, decryptedData);
		return true;
	}
	catch (Exception^)
	{
		return false;
	}
}



// ===== EXISTING ALGORITHM IMPLEMENTATIONS =====
// Note: Keep your existing AES, 3DES, RC4, ChaCha20, Blowfish implementations here
// They should remain exactly as in your original code


// ===== EXISTING ALGORITHM IMPLEMENTATIONS =====
// [All existing algorithm implementations remain the same as in the original code]
// AES, 3DES, RC4, ChaCha20, Blowfish implementations...

// Note: The existing algorithm implementations (AES, 3DES, RC4, ChaCha20, Blowfish)
// remain exactly the same as in your original code. I've omitted them here
// for brevity, but you should keep them in your MainForm.cpp file.

// ===== CUSTOM AES IMPLEMENTATION =====

// AES Helper Functions
UInt32 MainForm::AES_SubWord(UInt32 word)
{
	array<Byte>^ sbox = GetAES_SBOX();
	return (sbox[(word >> 24) & 0xFF] << 24) |
		(sbox[(word >> 16) & 0xFF] << 16) |
		(sbox[(word >> 8) & 0xFF] << 8) |
		sbox[word & 0xFF];
}

UInt32 MainForm::AES_RotWord(UInt32 word)
{
	return (word << 8) | (word >> 24);
}

void MainForm::AES_KeyExpansion(array<Byte>^ key, array<UInt32>^ w)
{
	int Nk = key->Length / 4;
	int Nr = Nk + 6;
	int i = 0;
	array<UInt32>^ rcon = GetAES_RCON();

	// Copy the original key
	for (i = 0; i < Nk; i++)
	{
		w[i] = (UInt32)(key[4 * i] << 24) | (UInt32)(key[4 * i + 1] << 16) |
			(UInt32)(key[4 * i + 2] << 8) | (UInt32)(key[4 * i + 3]);
	}

	// Expand the key
	for (i = Nk; i < 4 * (Nr + 1); i++)
	{
		UInt32 temp = w[i - 1];
		if (i % Nk == 0)
		{
			temp = AES_SubWord(AES_RotWord(temp)) ^ rcon[i / Nk - 1];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			temp = AES_SubWord(temp);
		}
		w[i] = w[i - Nk] ^ temp;
	}
}

void MainForm::AES_AddRoundKey(array<UInt32>^ state, array<UInt32>^ w, int round)
{
	for (int c = 0; c < 4; c++)
	{
		state[c] ^= w[round * 4 + c];
	}
}

void MainForm::AES_SubBytes(array<UInt32>^ state)
{
	array<Byte>^ sbox = GetAES_SBOX();
	for (int i = 0; i < 4; i++)
	{
		state[i] = (sbox[(state[i] >> 24) & 0xFF] << 24) |
			(sbox[(state[i] >> 16) & 0xFF] << 16) |
			(sbox[(state[i] >> 8) & 0xFF] << 8) |
			sbox[state[i] & 0xFF];
	}
}

void MainForm::AES_InvSubBytes(array<UInt32>^ state)
{
	array<Byte>^ inv_sbox = GetAES_INV_SBOX();
	for (int i = 0; i < 4; i++)
	{
		state[i] = (inv_sbox[(state[i] >> 24) & 0xFF] << 24) |
			(inv_sbox[(state[i] >> 16) & 0xFF] << 16) |
			(inv_sbox[(state[i] >> 8) & 0xFF] << 8) |
			inv_sbox[state[i] & 0xFF];
	}
}

void MainForm::AES_ShiftRows(array<UInt32>^ state)
{
	array<Byte>^ temp = gcnew array<Byte>(16);

	// Convert state to bytes
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
		}
	}

	// Shift rows
	for (int i = 1; i < 4; i++)
	{
		for (int j = 0; j < i; j++)
		{
			Byte t = temp[i * 4];
			temp[i * 4] = temp[i * 4 + 1];
			temp[i * 4 + 1] = temp[i * 4 + 2];
			temp[i * 4 + 2] = temp[i * 4 + 3];
			temp[i * 4 + 3] = t;
		}
	}

	// Convert back to words
	for (int i = 0; i < 4; i++)
	{
		state[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
		}
	}
}

void MainForm::AES_InvShiftRows(array<UInt32>^ state)
{
	array<Byte>^ temp = gcnew array<Byte>(16);

	// Convert state to bytes
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
		}
	}

	// Inverse shift rows
	for (int i = 1; i < 4; i++)
	{
		for (int j = 0; j < i; j++)
		{
			Byte t = temp[i * 4 + 3];
			temp[i * 4 + 3] = temp[i * 4 + 2];
			temp[i * 4 + 2] = temp[i * 4 + 1];
			temp[i * 4 + 1] = temp[i * 4];
			temp[i * 4] = t;
		}
	}

	// Convert back to words
	for (int i = 0; i < 4; i++)
	{
		state[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
		}
	}
}

Byte MainForm::AES_GFMultiply(Byte a, Byte b)
{
	Byte result = 0;
	Byte hiBit;

	for (int i = 0; i < 8; i++)
	{
		if ((b & 1) == 1)
			result ^= a;
		hiBit = (Byte)(a & 0x80);
		a <<= 1;
		if (hiBit == 0x80)
			a ^= 0x1B;
		b >>= 1;
	}

	return result;
}

void MainForm::AES_MixColumns(array<UInt32>^ state)
{
	array<Byte>^ temp = gcnew array<Byte>(16);

	// Convert state to bytes
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
		}
	}

	// Mix columns
	for (int i = 0; i < 4; i++)
	{
		Byte a0 = temp[i * 4];
		Byte a1 = temp[i * 4 + 1];
		Byte a2 = temp[i * 4 + 2];
		Byte a3 = temp[i * 4 + 3];

		temp[i * 4] = (Byte)(AES_GFMultiply(0x02, a0) ^ AES_GFMultiply(0x03, a1) ^ a2 ^ a3);
		temp[i * 4 + 1] = (Byte)(a0 ^ AES_GFMultiply(0x02, a1) ^ AES_GFMultiply(0x03, a2) ^ a3);
		temp[i * 4 + 2] = (Byte)(a0 ^ a1 ^ AES_GFMultiply(0x02, a2) ^ AES_GFMultiply(0x03, a3));
		temp[i * 4 + 3] = (Byte)(AES_GFMultiply(0x03, a0) ^ a1 ^ a2 ^ AES_GFMultiply(0x02, a3));
	}

	// Convert back to words
	for (int i = 0; i < 4; i++)
	{
		state[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
		}
	}
}

void MainForm::AES_InvMixColumns(array<UInt32>^ state)
{
	array<Byte>^ temp = gcnew array<Byte>(16);

	// Convert state to bytes
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			temp[i * 4 + j] = (Byte)((state[j] >> (24 - 8 * i)) & 0xFF);
		}
	}

	// Inverse mix columns
	for (int i = 0; i < 4; i++)
	{
		Byte a0 = temp[i * 4];
		Byte a1 = temp[i * 4 + 1];
		Byte a2 = temp[i * 4 + 2];
		Byte a3 = temp[i * 4 + 3];

		temp[i * 4] = (Byte)(AES_GFMultiply(0x0E, a0) ^ AES_GFMultiply(0x0B, a1) ^ AES_GFMultiply(0x0D, a2) ^ AES_GFMultiply(0x09, a3));
		temp[i * 4 + 1] = (Byte)(AES_GFMultiply(0x09, a0) ^ AES_GFMultiply(0x0E, a1) ^ AES_GFMultiply(0x0B, a2) ^ AES_GFMultiply(0x0D, a3));
		temp[i * 4 + 2] = (Byte)(AES_GFMultiply(0x0D, a0) ^ AES_GFMultiply(0x09, a1) ^ AES_GFMultiply(0x0E, a2) ^ AES_GFMultiply(0x0B, a3));
		temp[i * 4 + 3] = (Byte)(AES_GFMultiply(0x0B, a0) ^ AES_GFMultiply(0x0D, a1) ^ AES_GFMultiply(0x09, a2) ^ AES_GFMultiply(0x0E, a3));
	}

	// Convert back to words
	for (int i = 0; i < 4; i++)
	{
		state[i] = 0;
		for (int j = 0; j < 4; j++)
		{
			state[i] |= (UInt32)(temp[j * 4 + i] << (24 - 8 * j));
		}
	}
}

// Main AES Encryption/Decryption
array<Byte>^ MainForm::AES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length != 16 && key->Length != 24 && key->Length != 32)
	{
		throw gcnew ArgumentException("AES requires key sizes of 16, 24, or 32 bytes (128, 192, or 256 bits)");
	}

	if (iv->Length != 16)
	{
		throw gcnew ArgumentException("AES requires a 16-byte (128-bit) IV");
	}

	// Determine parameters based on key size
	int Nk = key->Length / 4;  // Number of 32-bit words in key
	int Nr = Nk + 6;           // Number of rounds

	// Expand key
	array<UInt32>^ w = gcnew array<UInt32>(4 * (Nr + 1));
	AES_KeyExpansion(key, w);

	// Pad data to multiple of 16 bytes using PKCS7
	int paddedLength = ((data->Length + 15) / 16) * 16;
	array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
	Array::Copy(data, paddedData, data->Length);

	Byte padValue = (Byte)(paddedLength - data->Length);
	for (int i = data->Length; i < paddedLength; i++)
	{
		paddedData[i] = padValue;
	}

	array<Byte>^ result = gcnew array<Byte>(paddedLength);
	array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

	// Process each 16-byte block
	for (int block = 0; block < paddedLength; block += 16)
	{
		array<Byte>^ blockData = gcnew array<Byte>(16);
		Array::Copy(paddedData, block, blockData, 0, 16);

		// XOR with previous block (CBC mode)
		for (int i = 0; i < 16; i++)
		{
			blockData[i] ^= previousBlock[i];
		}

		// Convert block to state (column-major order)
		array<UInt32>^ state = gcnew array<UInt32>(4);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				state[i] |= (UInt32)(blockData[j * 4 + i] << (24 - 8 * j));
			}
		}

		// AES Encryption Rounds
		AES_AddRoundKey(state, w, 0);

		for (int round = 1; round < Nr; round++)
		{
			AES_SubBytes(state);
			AES_ShiftRows(state);
			AES_MixColumns(state);
			AES_AddRoundKey(state, w, round);
		}

		// Final round (no MixColumns)
		AES_SubBytes(state);
		AES_ShiftRows(state);
		AES_AddRoundKey(state, w, Nr);

		// Convert state back to bytes
		array<Byte>^ encryptedBlock = gcnew array<Byte>(16);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				encryptedBlock[j * 4 + i] = (Byte)((state[i] >> (24 - 8 * j)) & 0xFF);
			}
		}

		Array::Copy(encryptedBlock, 0, result, block, 16);
		previousBlock = encryptedBlock;
	}

	return result;
}

array<Byte>^ MainForm::AES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length != 16 && key->Length != 24 && key->Length != 32)
	{
		throw gcnew ArgumentException("AES requires key sizes of 16, 24, or 32 bytes (128, 192, or 256 bits)");
	}

	if (iv->Length != 16)
	{
		throw gcnew ArgumentException("AES requires a 16-byte (128-bit) IV");
	}

	if (data->Length % 16 != 0)
	{
		throw gcnew ArgumentException("AES encrypted data must be multiple of 16 bytes");
	}

	// Determine parameters based on key size
	int Nk = key->Length / 4;  // Number of 32-bit words in key
	int Nr = Nk + 6;           // Number of rounds

	// Expand key
	array<UInt32>^ w = gcnew array<UInt32>(4 * (Nr + 1));
	AES_KeyExpansion(key, w);

	array<Byte>^ result = gcnew array<Byte>(data->Length);
	array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

	// Process each 16-byte block
	for (int block = 0; block < data->Length; block += 16)
	{
		array<Byte>^ blockData = gcnew array<Byte>(16);
		Array::Copy(data, block, blockData, 0, 16);

		array<Byte>^ tempBlock = (array<Byte>^)blockData->Clone();

		// Convert block to state (column-major order)
		array<UInt32>^ state = gcnew array<UInt32>(4);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				state[i] |= (UInt32)(blockData[j * 4 + i] << (24 - 8 * j));
			}
		}

		// AES Decryption Rounds
		AES_AddRoundKey(state, w, Nr);
		AES_InvShiftRows(state);
		AES_InvSubBytes(state);

		for (int round = Nr - 1; round >= 1; round--)
		{
			AES_AddRoundKey(state, w, round);
			AES_InvMixColumns(state);
			AES_InvShiftRows(state);
			AES_InvSubBytes(state);
		}

		AES_AddRoundKey(state, w, 0);

		// Convert state back to bytes
		array<Byte>^ decryptedBlock = gcnew array<Byte>(16);
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				decryptedBlock[j * 4 + i] = (Byte)((state[i] >> (24 - 8 * j)) & 0xFF);
			}
		}

		// XOR with previous block (CBC mode)
		for (int i = 0; i < 16; i++)
		{
			decryptedBlock[i] ^= previousBlock[i];
			result[block + i] = decryptedBlock[i];
		}

		previousBlock = tempBlock;
	}

	// Remove PKCS7 padding
	Byte padValue = result[result->Length - 1];
	if (padValue > 0 && padValue <= 16)
	{
		bool validPadding = true;
		for (int i = result->Length - padValue; i < result->Length; i++)
		{
			if (result[i] != padValue)
			{
				validPadding = false;
				break;
			}
		}
		if (validPadding)
		{
			array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
			Array::Copy(result, unpaddedResult, unpaddedResult->Length);
			return unpaddedResult;
		}
	}

	return result;
}

// ===== CUSTOM 3DES IMPLEMENTATION =====

// 3DES Helper Functions
UInt64 MainForm::DES_Permute(UInt64 data, array<Byte>^ table, int inputSize)
{
	UInt64 result = 0;
	for (int i = 0; i < table->Length; i++)
	{
		int bitPos = inputSize - table[i];
		if ((data & (1ULL << bitPos)) != 0)
		{
			result |= (1ULL << (table->Length - 1 - i));
		}
	}
	return result;
}

void MainForm::DES_GenerateSubkeys(UInt64 key, array<UInt64>^ subkeys)
{
	array<Byte>^ pc1 = GetDES_PC1();
	array<Byte>^ pc2 = GetDES_PC2();
	array<Byte>^ shifts = GetDES_SHIFTS();

	// Apply PC1 permutation
	UInt64 permutedKey = DES_Permute(key, pc1, 64);

	UInt32 left = (UInt32)(permutedKey >> 28) & 0x0FFFFFFF;
	UInt32 right = (UInt32)(permutedKey & 0x0FFFFFFF);

	for (int i = 0; i < 16; i++)
	{
		// Apply shifts
		left = ((left << shifts[i]) | (left >> (28 - shifts[i]))) & 0x0FFFFFFF;
		right = ((right << shifts[i]) | (right >> (28 - shifts[i]))) & 0x0FFFFFFF;

		// Combine and apply PC2
		UInt64 combined = ((UInt64)left << 28) | right;
		subkeys[i] = DES_Permute(combined, pc2, 56);
	}
}

UInt32 MainForm::DES_Function(UInt32 right, UInt64 subkey)
{
	array<Byte>^ e = GetDES_E();
	array<Byte>^ p = GetDES_P();
	array<array<Byte>^>^ sboxes = GetDES_SBOX();

	// Expand right half to 48 bits
	UInt64 expanded = DES_Permute(right, e, 32);

	// XOR with subkey
	expanded ^= subkey;

	// Apply S-boxes
	UInt32 result = 0;
	for (int i = 0; i < 8; i++)
	{
		int shift = 42 - 6 * i;
		int sboxInput = (int)((expanded >> shift) & 0x3F);
		int row = ((sboxInput & 0x20) >> 4) | (sboxInput & 0x01);
		int col = (sboxInput >> 1) & 0x0F;
		int sboxOutput = sboxes[i][row * 16 + col];
		result |= (UInt32)(sboxOutput << (28 - 4 * i));
	}

	// Apply P permutation
	return (UInt32)DES_Permute(result, p, 32);
}

UInt64 MainForm::DES_ProcessBlock(UInt64 block, array<UInt64>^ subkeys, bool encrypt)
{
	array<Byte>^ ip = GetDES_IP();
	array<Byte>^ fp = GetDES_FP();

	// Apply initial permutation
	block = DES_Permute(block, ip, 64);

	UInt32 left = (UInt32)(block >> 32);
	UInt32 right = (UInt32)(block & 0xFFFFFFFF);

	// 16 rounds
	for (int i = 0; i < 16; i++)
	{
		int round = encrypt ? i : 15 - i;
		UInt64 subkey = subkeys[round];

		UInt32 newRight = left ^ DES_Function(right, subkey);
		left = right;
		right = newRight;
	}

	// Final swap and apply final permutation
	UInt64 result = ((UInt64)right << 32) | left;
	return DES_Permute(result, fp, 64);
}

// 3DES Main Functions
array<Byte>^ MainForm::TripleDES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length != 16 && key->Length != 24)
	{
		throw gcnew ArgumentException("3DES requires key sizes of 16 or 24 bytes (112 or 168 bits)");
	}

	if (iv->Length != 8)
	{
		throw gcnew ArgumentException("3DES requires an 8-byte IV");
	}

	// Prepare keys
	array<UInt64>^ keys = gcnew array<UInt64>(3);

	if (key->Length == 16)
	{
		// 2-key 3DES: K1 = first 8 bytes, K2 = last 8 bytes, K3 = first 8 bytes
		keys[0] = BitConverter::ToUInt64(key, 0);
		keys[1] = BitConverter::ToUInt64(key, 8);
		keys[2] = keys[0];
	}
	else
	{
		// 3-key 3DES: K1, K2, K3 from 24 bytes
		keys[0] = BitConverter::ToUInt64(key, 0);
		keys[1] = BitConverter::ToUInt64(key, 8);
		keys[2] = BitConverter::ToUInt64(key, 16);
	}

	// Generate subkeys for each key
	array<array<UInt64>^>^ subkeys = gcnew array<array<UInt64>^>(3);
	for (int i = 0; i < 3; i++)
	{
		subkeys[i] = gcnew array<UInt64>(16);
		DES_GenerateSubkeys(keys[i], subkeys[i]);
	}

	// Pad data to multiple of 8 bytes using PKCS7
	int paddedLength = ((data->Length + 7) / 8) * 8;
	array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
	Array::Copy(data, paddedData, data->Length);

	Byte padValue = (Byte)(paddedLength - data->Length);
	for (int i = data->Length; i < paddedLength; i++)
	{
		paddedData[i] = padValue;
	}

	array<Byte>^ result = gcnew array<Byte>(paddedLength);
	UInt64 previousBlock = BitConverter::ToUInt64(iv, 0);

	// Process each 8-byte block
	for (int block = 0; block < paddedLength; block += 8)
	{
		UInt64 blockData = BitConverter::ToUInt64(paddedData, block);

		// CBC mode: XOR with previous block
		blockData ^= previousBlock;

		// 3DES: Encrypt with K1, Decrypt with K2, Encrypt with K3
		UInt64 encrypted = DES_ProcessBlock(blockData, subkeys[0], true);  // Encrypt with K1
		encrypted = DES_ProcessBlock(encrypted, subkeys[1], false);        // Decrypt with K2
		encrypted = DES_ProcessBlock(encrypted, subkeys[2], true);         // Encrypt with K3

		array<Byte>^ encryptedBytes = BitConverter::GetBytes(encrypted);
		Array::Copy(encryptedBytes, 0, result, block, 8);

		previousBlock = encrypted;
	}

	return result;
}

array<Byte>^ MainForm::TripleDES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length != 16 && key->Length != 24)
	{
		throw gcnew ArgumentException("3DES requires key sizes of 16 or 24 bytes (112 or 168 bits)");
	}

	if (iv->Length != 8)
	{
		throw gcnew ArgumentException("3DES requires an 8-byte IV");
	}

	if (data->Length % 8 != 0)
	{
		throw gcnew ArgumentException("3DES encrypted data must be multiple of 8 bytes");
	}

	// Prepare keys (same as encryption)
	array<UInt64>^ keys = gcnew array<UInt64>(3);

	if (key->Length == 16)
	{
		keys[0] = BitConverter::ToUInt64(key, 0);
		keys[1] = BitConverter::ToUInt64(key, 8);
		keys[2] = keys[0];
	}
	else
	{
		keys[0] = BitConverter::ToUInt64(key, 0);
		keys[1] = BitConverter::ToUInt64(key, 8);
		keys[2] = BitConverter::ToUInt64(key, 16);
	}

	// Generate subkeys for each key
	array<array<UInt64>^>^ subkeys = gcnew array<array<UInt64>^>(3);
	for (int i = 0; i < 3; i++)
	{
		subkeys[i] = gcnew array<UInt64>(16);
		DES_GenerateSubkeys(keys[i], subkeys[i]);
	}

	array<Byte>^ result = gcnew array<Byte>(data->Length);
	UInt64 previousBlock = BitConverter::ToUInt64(iv, 0);

	// Process each 8-byte block
	for (int block = 0; block < data->Length; block += 8)
	{
		UInt64 blockData = BitConverter::ToUInt64(data, block);
		UInt64 tempBlock = blockData;

		// 3DES: Decrypt with K3, Encrypt with K2, Decrypt with K1
		UInt64 decrypted = DES_ProcessBlock(blockData, subkeys[2], false); // Decrypt with K3
		decrypted = DES_ProcessBlock(decrypted, subkeys[1], true);         // Encrypt with K2
		decrypted = DES_ProcessBlock(decrypted, subkeys[0], false);        // Decrypt with K1

		// CBC mode: XOR with previous block
		decrypted ^= previousBlock;

		array<Byte>^ decryptedBytes = BitConverter::GetBytes(decrypted);
		Array::Copy(decryptedBytes, 0, result, block, 8);

		previousBlock = tempBlock;
	}

	// Remove PKCS7 padding
	Byte padValue = result[result->Length - 1];
	if (padValue > 0 && padValue <= 8)
	{
		bool validPadding = true;
		for (int i = result->Length - padValue; i < result->Length; i++)
		{
			if (result[i] != padValue)
			{
				validPadding = false;
				break;
			}
		}
		if (validPadding)
		{
			array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
			Array::Copy(result, unpaddedResult, unpaddedResult->Length);
			return unpaddedResult;
		}
	}

	return result;
}

// ===== EXISTING ALGORITHMS (RC4, ChaCha20, Blowfish) =====

array<Byte>^ MainForm::RC4_Encrypt(array<Byte>^ data, array<Byte>^ key)
{
	array<Byte>^ result = gcnew array<Byte>(data->Length);
	array<int>^ s = gcnew array<int>(256);

	for (int i = 0; i < 256; i++)
	{
		s[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; i++)
	{
		j = (j + s[i] + key[i % key->Length]) % 256;
		int temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}

	int i_index = 0;
	j = 0;
	for (int k = 0; k < data->Length; k++)
	{
		i_index = (i_index + 1) % 256;
		j = (j + s[i_index]) % 256;

		int temp = s[i_index];
		s[i_index] = s[j];
		s[j] = temp;

		int t = (s[i_index] + s[j]) % 256;
		result[k] = data[k] ^ (Byte)s[t];
	}

	return result;
}

array<Byte>^ MainForm::RC4_Decrypt(array<Byte>^ data, array<Byte>^ key)
{
	return RC4_Encrypt(data, key);
}

UInt32 MainForm::RotateLeft(UInt32 value, int offset)
{
	return (value << offset) | (value >> (32 - offset));
}

void MainForm::QuarterRound(array<UInt32>^ state, int a, int b, int c, int d)
{
	state[a] += state[b]; state[d] = RotateLeft(state[d] ^ state[a], 16);
	state[c] += state[d]; state[b] = RotateLeft(state[b] ^ state[c], 12);
	state[a] += state[b]; state[d] = RotateLeft(state[d] ^ state[a], 8);
	state[c] += state[d]; state[b] = RotateLeft(state[b] ^ state[c], 7);
}

array<Byte>^ MainForm::ChaCha20_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce)
{
	if (key->Length != 16 && key->Length != 32)
	{
		throw gcnew ArgumentException("ChaCha20 requires key sizes of 16 or 32 bytes (128 or 256 bits)");
	}

	array<Byte>^ result = gcnew array<Byte>(data->Length);
	array<UInt32>^ state = gcnew array<UInt32>(16);

	// ChaCha20 constants
	state[0] = 0x61707865;  // "expa"
	state[1] = 0x3320646e;  // "nd 3"
	state[2] = 0x79622d32;  // "2-by"
	state[3] = 0x6b206574;  // "te k"

	// Key setup - handle both 128-bit and 256-bit keys
	if (key->Length == 16)
	{
		// For 128-bit key, use the key twice (as in RFC7539)
		for (int i = 0; i < 4; i++)
		{
			state[4 + i] = BitConverter::ToUInt32(key, i * 4);
			state[8 + i] = BitConverter::ToUInt32(key, i * 4);
		}
	}
	else
	{
		// For 256-bit key
		for (int i = 0; i < 8; i++)
		{
			state[4 + i] = BitConverter::ToUInt32(key, i * 4);
		}
	}

	// Counter (set to 0)
	state[12] = 0;

	// Nonce (96 bits)
	for (int i = 0; i < 3; i++)
	{
		state[13 + i] = BitConverter::ToUInt32(nonce, i * 4);
	}

	int blockCount = (data->Length + 63) / 64;
	for (int block = 0; block < blockCount; block++)
	{
		state[12] = (UInt32)block;
		array<UInt32>^ workingState = (array<UInt32>^)state->Clone();

		// 20 rounds (10 double rounds)
		for (int round = 0; round < 10; round++)
		{
			// Column rounds
			QuarterRound(workingState, 0, 4, 8, 12);
			QuarterRound(workingState, 1, 5, 9, 13);
			QuarterRound(workingState, 2, 6, 10, 14);
			QuarterRound(workingState, 3, 7, 11, 15);

			// Diagonal rounds
			QuarterRound(workingState, 0, 5, 10, 15);
			QuarterRound(workingState, 1, 6, 11, 12);
			QuarterRound(workingState, 2, 7, 8, 13);
			QuarterRound(workingState, 3, 4, 9, 14);
		}

		// Add initial state to working state
		for (int i = 0; i < 16; i++)
		{
			workingState[i] += state[i];
		}

		// Convert state to byte array
		array<Byte>^ keyStream = gcnew array<Byte>(64);
		for (int i = 0; i < 16; i++)
		{
			array<Byte>^ word = BitConverter::GetBytes(workingState[i]);
			Array::Copy(word, 0, keyStream, i * 4, 4);
		}

		// XOR with data
		int blockStart = block * 64;
		int blockSize = Math::Min(64, data->Length - blockStart);
		for (int i = 0; i < blockSize; i++)
		{
			result[blockStart + i] = (Byte)(data[blockStart + i] ^ keyStream[i]);
		}
	}

	return result;
}

array<Byte>^ MainForm::ChaCha20_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce)
{
	return ChaCha20_Encrypt(data, key, nonce);
}

// Blowfish F function
UInt32 MainForm::F(UInt32 x)
{
	UInt32 a = (x >> 24) & 0xFF;
	UInt32 b = (x >> 16) & 0xFF;
	UInt32 c = (x >> 8) & 0xFF;
	UInt32 d = x & 0xFF;

	UInt32 y = S[0][a] + S[1][b];
	y = y ^ S[2][c];
	y = y + S[3][d];

	return y;
}

// Blowfish encryption for a single 64-bit block
void MainForm::EncryptBlock(array<UInt32>^ block)
{
	UInt32 left = block[0];
	UInt32 right = block[1];

	for (int i = 0; i < 16; i++)
	{
		left ^= P[i];
		right ^= F(left);

		// Swap
		UInt32 temp = left;
		left = right;
		right = temp;
	}

	// Final swap and XOR
	UInt32 temp = left;
	left = right;
	right = temp;

	right ^= P[16];
	left ^= P[17];

	block[0] = left;
	block[1] = right;
}

// Blowfish decryption for a single 64-bit block
void MainForm::DecryptBlock(array<UInt32>^ block)
{
	UInt32 left = block[0];
	UInt32 right = block[1];

	for (int i = 17; i > 1; i--)
	{
		left ^= P[i];
		right ^= F(left);

		// Swap
		UInt32 temp = left;
		left = right;
		right = temp;
	}

	// Final swap and XOR
	UInt32 temp = left;
	left = right;
	right = temp;

	right ^= P[1];
	left ^= P[0];

	block[0] = left;
	block[1] = right;
}

// Initialize Blowfish with key
void MainForm::InitializeBlowfish(array<Byte>^ key)
{
	array<UInt32>^ p_init = GetP_INIT();
	array<UInt32>^ s_init = GetS_INIT();

	// Initialize P and S arrays with initial values
	for (int i = 0; i < 18; i++)
	{
		P[i] = p_init[i];
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 256; j++)
		{
			S[i][j] = s_init[i * 256 + j];
		}
	}

	// XOR P array with key
	int keyIndex = 0;
	for (int i = 0; i < 18; i++)
	{
		UInt32 data = 0;
		for (int j = 0; j < 4; j++)
		{
			data = (data << 8) | key[keyIndex];
			keyIndex = (keyIndex + 1) % key->Length;
		}
		P[i] ^= data;
	}

	// Encrypt zero blocks to further randomize P and S arrays
	array<UInt32>^ block = gcnew array<UInt32>(2);
	block[0] = 0;
	block[1] = 0;

	for (int i = 0; i < 18; i += 2)
	{
		EncryptBlock(block);
		P[i] = block[0];
		P[i + 1] = block[1];
	}

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 256; j += 2)
		{
			EncryptBlock(block);
			S[i][j] = block[0];
			S[i][j + 1] = block[1];
		}
	}
}

array<Byte>^ MainForm::Blowfish_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length < 4 || key->Length > 56)
	{
		throw gcnew ArgumentException("Blowfish requires key sizes between 4 and 56 bytes (32-448 bits)");
	}

	// Initialize Blowfish with the key
	InitializeBlowfish(key);

	// Pad data to multiple of 8 bytes using PKCS7
	int paddedLength = ((data->Length + 7) / 8) * 8;
	array<Byte>^ paddedData = gcnew array<Byte>(paddedLength);
	Array::Copy(data, paddedData, data->Length);

	// PKCS7 padding
	Byte padValue = (Byte)(paddedLength - data->Length);
	for (int i = data->Length; i < paddedLength; i++)
	{
		paddedData[i] = padValue;
	}

	array<Byte>^ result = gcnew array<Byte>(paddedLength);
	array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

	for (int i = 0; i < paddedLength; i += 8)
	{
		array<Byte>^ block = gcnew array<Byte>(8);
		Array::Copy(paddedData, i, block, 0, 8);

		// XOR with previous block (CBC mode)
		for (int j = 0; j < 8; j++)
		{
			block[j] ^= previousBlock[j];
		}

		// Convert to 32-bit words for encryption
		array<UInt32>^ words = gcnew array<UInt32>(2);
		words[0] = (UInt32)(block[0] << 24) | (UInt32)(block[1] << 16) | (UInt32)(block[2] << 8) | block[3];
		words[1] = (UInt32)(block[4] << 24) | (UInt32)(block[5] << 16) | (UInt32)(block[6] << 8) | block[7];

		// Encrypt the block
		EncryptBlock(words);

		// Convert back to bytes
		array<Byte>^ encryptedBlock = gcnew array<Byte>(8);
		encryptedBlock[0] = (Byte)((words[0] >> 24) & 0xFF);
		encryptedBlock[1] = (Byte)((words[0] >> 16) & 0xFF);
		encryptedBlock[2] = (Byte)((words[0] >> 8) & 0xFF);
		encryptedBlock[3] = (Byte)(words[0] & 0xFF);
		encryptedBlock[4] = (Byte)((words[1] >> 24) & 0xFF);
		encryptedBlock[5] = (Byte)((words[1] >> 16) & 0xFF);
		encryptedBlock[6] = (Byte)((words[1] >> 8) & 0xFF);
		encryptedBlock[7] = (Byte)(words[1] & 0xFF);

		Array::Copy(encryptedBlock, 0, result, i, 8);
		previousBlock = encryptedBlock;
	}

	return result;
}

array<Byte>^ MainForm::Blowfish_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv)
{
	if (key->Length < 4 || key->Length > 56)
	{
		throw gcnew ArgumentException("Blowfish requires key sizes between 4 and 56 bytes (32-448 bits)");
	}

	if (data->Length % 8 != 0)
	{
		throw gcnew ArgumentException("Blowfish encrypted data must be multiple of 8 bytes");
	}

	InitializeBlowfish(key);

	array<Byte>^ result = gcnew array<Byte>(data->Length);
	array<Byte>^ previousBlock = (array<Byte>^)iv->Clone();

	for (int i = 0; i < data->Length; i += 8)
	{
		array<Byte>^ block = gcnew array<Byte>(8);
		Array::Copy(data, i, block, 0, 8);

		array<Byte>^ tempBlock = (array<Byte>^)block->Clone();

		array<UInt32>^ words = gcnew array<UInt32>(2);
		words[0] = (UInt32)(block[0] << 24) | (UInt32)(block[1] << 16) | (UInt32)(block[2] << 8) | block[3];
		words[1] = (UInt32)(block[4] << 24) | (UInt32)(block[5] << 16) | (UInt32)(block[6] << 8) | block[7];

		DecryptBlock(words);

		array<Byte>^ decryptedBlock = gcnew array<Byte>(8);
		decryptedBlock[0] = (Byte)((words[0] >> 24) & 0xFF);
		decryptedBlock[1] = (Byte)((words[0] >> 16) & 0xFF);
		decryptedBlock[2] = (Byte)((words[0] >> 8) & 0xFF);
		decryptedBlock[3] = (Byte)(words[0] & 0xFF);
		decryptedBlock[4] = (Byte)((words[1] >> 24) & 0xFF);
		decryptedBlock[5] = (Byte)((words[1] >> 16) & 0xFF);
		decryptedBlock[6] = (Byte)((words[1] >> 8) & 0xFF);
		decryptedBlock[7] = (Byte)(words[1] & 0xFF);

		for (int j = 0; j < 8; j++)
		{
			decryptedBlock[j] ^= previousBlock[j];
			result[i + j] = decryptedBlock[j];
		}

		previousBlock = tempBlock;
	}

	// Remove PKCS7 padding
	Byte padValue = result[result->Length - 1];
	if (padValue > 0 && padValue <= 8)
	{
		bool validPadding = true;
		for (int i = result->Length - padValue; i < result->Length; i++)
		{
			if (result[i] != padValue)
			{
				validPadding = false;
				break;
			}
		}
		if (validPadding)
		{
			array<Byte>^ unpaddedResult = gcnew array<Byte>(result->Length - padValue);
			Array::Copy(result, unpaddedResult, unpaddedResult->Length);
			return unpaddedResult;
		}
	}

	return result;
}