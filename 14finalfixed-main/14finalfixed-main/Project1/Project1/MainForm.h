#pragma once

namespace EncryptionTool {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::IO;
	using namespace System::Security::Cryptography;
	using namespace System::Text;
	using namespace System::Numerics;
	using namespace System::Collections::Generic;

	public ref class MainForm : public System::Windows::Forms::Form
	{
	public:
		MainForm(void)
		{
			InitializeComponent();
			encryptionAlgorithms = gcnew array<String^>{ "AES", "RC4", "ChaCha20", "Blowfish", "3DES", "RSA", "ECC-256" };
			InitializeEncryption();

			// Initialize Blowfish arrays
			P = gcnew array<UInt32>(18);
			S = gcnew array<array<UInt32>^>(4);
			for (int i = 0; i < 4; i++) {
				S[i] = gcnew array<UInt32>(256);
			}

			// Initialize ECC P-256 parameters
			InitializeECC_P256();
		}

	protected:
		~MainForm()
		{
			if (components)
			{
				delete components;
			}
		}

	private:
		array<String^>^ encryptionAlgorithms;
		String^ key;
		String^ iv;

		System::Windows::Forms::Label^ label1;
		System::Windows::Forms::TextBox^ textBox1;
		System::Windows::Forms::Label^ label2;
		System::Windows::Forms::ComboBox^ comboBox1;
		System::Windows::Forms::Label^ label3;
		System::Windows::Forms::Button^ button1;
		System::Windows::Forms::Button^ button2;
		System::Windows::Forms::Label^ label4;
		System::Windows::Forms::Label^ label5;
		System::Windows::Forms::Label^ label6;
		System::Windows::Forms::TextBox^ textBox2;
		System::Windows::Forms::Button^ button3;
		System::Windows::Forms::Button^ button4;
		System::Windows::Forms::Button^ button5;
		System::Windows::Forms::Label^ label7;
		System::Windows::Forms::RichTextBox^ richTextBox1;
		System::Windows::Forms::TextBox^ textBoxKey;
		System::Windows::Forms::Label^ label8;
		System::Windows::Forms::Button^ buttonGenerateKey;
		System::Windows::Forms::Label^ labelKeyInfo;
		System::Windows::Forms::RadioButton^ radioTextKey;
		System::Windows::Forms::RadioButton^ radioHexKey;
		System::Windows::Forms::Panel^ panelKeyType;
		System::Windows::Forms::TextBox^ textBoxPublicKey;
		System::Windows::Forms::TextBox^ textBoxPrivateKey;
		System::Windows::Forms::Label^ label9;
		System::Windows::Forms::Label^ label10;
		System::Windows::Forms::Button^ buttonGenerateRSAKeys;
		System::Windows::Forms::Panel^ panelRSAKeys;
		System::Windows::Forms::Button^ buttonImportPublic;
		System::Windows::Forms::Button^ buttonImportPrivate;
		System::Windows::Forms::Button^ buttonExportPublic;
		System::Windows::Forms::Button^ buttonExportPrivate;

		// ECC Controls
		System::Windows::Forms::Panel^ panelECCKeys;
		System::Windows::Forms::TextBox^ textBoxECCPublicKey;
		System::Windows::Forms::TextBox^ textBoxECCPrivateKey;
		System::Windows::Forms::Label^ label11;
		System::Windows::Forms::Label^ label12;
		System::Windows::Forms::Button^ buttonGenerateECCKeys;
		System::Windows::Forms::Button^ buttonImportECCPublic;
		System::Windows::Forms::Button^ buttonImportECCPrivate;
		System::Windows::Forms::Button^ buttonExportECCPublic;
		System::Windows::Forms::Button^ buttonExportECCPrivate;

		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		void InitializeComponent(void)
		{
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->comboBox1 = (gcnew System::Windows::Forms::ComboBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->button3 = (gcnew System::Windows::Forms::Button());
			this->button4 = (gcnew System::Windows::Forms::Button());
			this->button5 = (gcnew System::Windows::Forms::Button());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->richTextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->textBoxKey = (gcnew System::Windows::Forms::TextBox());
			this->label8 = (gcnew System::Windows::Forms::Label());
			this->buttonGenerateKey = (gcnew System::Windows::Forms::Button());
			this->labelKeyInfo = (gcnew System::Windows::Forms::Label());
			this->radioTextKey = (gcnew System::Windows::Forms::RadioButton());
			this->radioHexKey = (gcnew System::Windows::Forms::RadioButton());
			this->panelKeyType = (gcnew System::Windows::Forms::Panel());
			this->panelRSAKeys = (gcnew System::Windows::Forms::Panel());
			this->buttonExportPrivate = (gcnew System::Windows::Forms::Button());
			this->buttonExportPublic = (gcnew System::Windows::Forms::Button());
			this->buttonImportPrivate = (gcnew System::Windows::Forms::Button());
			this->buttonImportPublic = (gcnew System::Windows::Forms::Button());
			this->buttonGenerateRSAKeys = (gcnew System::Windows::Forms::Button());
			this->label10 = (gcnew System::Windows::Forms::Label());
			this->label9 = (gcnew System::Windows::Forms::Label());
			this->textBoxPrivateKey = (gcnew System::Windows::Forms::TextBox());
			this->textBoxPublicKey = (gcnew System::Windows::Forms::TextBox());
			this->panelECCKeys = (gcnew System::Windows::Forms::Panel());
			this->buttonExportECCPrivate = (gcnew System::Windows::Forms::Button());
			this->buttonExportECCPublic = (gcnew System::Windows::Forms::Button());
			this->buttonImportECCPrivate = (gcnew System::Windows::Forms::Button());
			this->buttonImportECCPublic = (gcnew System::Windows::Forms::Button());
			this->buttonGenerateECCKeys = (gcnew System::Windows::Forms::Button());
			this->label12 = (gcnew System::Windows::Forms::Label());
			this->label11 = (gcnew System::Windows::Forms::Label());
			this->textBoxECCPrivateKey = (gcnew System::Windows::Forms::TextBox());
			this->textBoxECCPublicKey = (gcnew System::Windows::Forms::TextBox());
			this->panelKeyType->SuspendLayout();
			this->panelRSAKeys->SuspendLayout();
			this->panelECCKeys->SuspendLayout();
			this->SuspendLayout();
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label1->Location = System::Drawing::Point(20, 20);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(173, 16);
			this->label1->TabIndex = 0;
			this->label1->Text = L"Text to Encrypt/Decrypt:";
			// 
			// textBox1
			// 
			this->textBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox1->Location = System::Drawing::Point(23, 50);
			this->textBox1->Multiline = true;
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(740, 80);
			this->textBox1->TabIndex = 1;
			this->textBox1->Text = L"Enter your text here...";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label2->Location = System::Drawing::Point(20, 150);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(124, 16);
			this->label2->TabIndex = 2;
			this->label2->Text = L"Select Algorithm:";
			// 
			// comboBox1
			// 
			this->comboBox1->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
			this->comboBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->comboBox1->FormattingEnabled = true;
			this->comboBox1->Location = System::Drawing::Point(23, 170);
			this->comboBox1->Name = L"comboBox1";
			this->comboBox1->Size = System::Drawing::Size(130, 23);
			this->comboBox1->TabIndex = 3;
			this->comboBox1->SelectedIndexChanged += gcnew System::EventHandler(this, &MainForm::comboBox1_SelectedIndexChanged);
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label3->Location = System::Drawing::Point(170, 150);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(37, 16);
			this->label3->TabIndex = 5;
			this->label3->Text = L"Key:";
			// 
			// button1
			// 
			this->button1->BackColor = System::Drawing::Color::LightGreen;
			this->button1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->button1->Location = System::Drawing::Point(320, 200);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(110, 30);
			this->button1->TabIndex = 6;
			this->button1->Text = L"Encrypt String";
			this->button1->UseVisualStyleBackColor = false;
			this->button1->Click += gcnew System::EventHandler(this, &MainForm::button1_Click);
			// 
			// button2
			// 
			this->button2->BackColor = System::Drawing::Color::LightBlue;
			this->button2->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->button2->Location = System::Drawing::Point(440, 200);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(110, 30);
			this->button2->TabIndex = 7;
			this->button2->Text = L"Decrypt String";
			this->button2->UseVisualStyleBackColor = false;
			this->button2->Click += gcnew System::EventHandler(this, &MainForm::button2_Click);
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label4->Location = System::Drawing::Point(20, 250);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(28, 13);
			this->label4->TabIndex = 8;
			this->label4->Text = L"Key:";
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label5->Location = System::Drawing::Point(20, 270);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(20, 13);
			this->label5->TabIndex = 9;
			this->label5->Text = L"IV:";
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label6->Location = System::Drawing::Point(20, 300);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(117, 16);
			this->label6->TabIndex = 10;
			this->label6->Text = L"File Operations:";
			// 
			// textBox2
			// 
			this->textBox2->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox2->Location = System::Drawing::Point(23, 330);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(590, 21);
			this->textBox2->TabIndex = 11;
			this->textBox2->Text = L"Select a file...";
			// 
			// button3
			// 
			this->button3->BackColor = System::Drawing::Color::LightGray;
			this->button3->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->button3->Location = System::Drawing::Point(625, 328);
			this->button3->Name = L"button3";
			this->button3->Size = System::Drawing::Size(80, 25);
			this->button3->TabIndex = 12;
			this->button3->Text = L"Browse";
			this->button3->UseVisualStyleBackColor = false;
			this->button3->Click += gcnew System::EventHandler(this, &MainForm::button3_Click);
			// 
			// button4
			// 
			this->button4->BackColor = System::Drawing::Color::LightGreen;
			this->button4->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->button4->Location = System::Drawing::Point(23, 365);
			this->button4->Name = L"button4";
			this->button4->Size = System::Drawing::Size(110, 30);
			this->button4->TabIndex = 13;
			this->button4->Text = L"Encrypt File";
			this->button4->UseVisualStyleBackColor = false;
			this->button4->Click += gcnew System::EventHandler(this, &MainForm::button4_Click);
			// 
			// button5
			// 
			this->button5->BackColor = System::Drawing::Color::LightBlue;
			this->button5->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->button5->Location = System::Drawing::Point(145, 365);
			this->button5->Name = L"button5";
			this->button5->Size = System::Drawing::Size(110, 30);
			this->button5->TabIndex = 14;
			this->button5->Text = L"Decrypt File";
			this->button5->UseVisualStyleBackColor = false;
			this->button5->Click += gcnew System::EventHandler(this, &MainForm::button5_Click);
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label7->Location = System::Drawing::Point(20, 415);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(63, 16);
			this->label7->TabIndex = 15;
			this->label7->Text = L"Results:";
			// 
			// richTextBox1
			// 
			this->richTextBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox1->Location = System::Drawing::Point(23, 445);
			this->richTextBox1->Name = L"richTextBox1";
			this->richTextBox1->ReadOnly = true;
			this->richTextBox1->Size = System::Drawing::Size(740, 180);
			this->richTextBox1->TabIndex = 16;
			this->richTextBox1->Text = L"";
			// 
			// textBoxKey
			// 
			this->textBoxKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBoxKey->Location = System::Drawing::Point(170, 170);
			this->textBoxKey->Name = L"textBoxKey";
			this->textBoxKey->Size = System::Drawing::Size(300, 21);
			this->textBoxKey->TabIndex = 17;
			this->textBoxKey->TextChanged += gcnew System::EventHandler(this, &MainForm::textBoxKey_TextChanged);
			// 
			// label8
			// 
			this->label8->AutoSize = true;
			this->label8->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label8->Location = System::Drawing::Point(485, 150);
			this->label8->Name = L"label8";
			this->label8->Size = System::Drawing::Size(117, 16);
			this->label8->TabIndex = 18;
			this->label8->Text = L"Key Information:";
			// 
			// buttonGenerateKey
			// 
			this->buttonGenerateKey->BackColor = System::Drawing::Color::LightYellow;
			this->buttonGenerateKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->buttonGenerateKey->Location = System::Drawing::Point(556, 200);
			this->buttonGenerateKey->Name = L"buttonGenerateKey";
			this->buttonGenerateKey->Size = System::Drawing::Size(110, 30);
			this->buttonGenerateKey->TabIndex = 19;
			this->buttonGenerateKey->Text = L"Generate Key";
			this->buttonGenerateKey->UseVisualStyleBackColor = false;
			this->buttonGenerateKey->Click += gcnew System::EventHandler(this, &MainForm::buttonGenerateKey_Click);
			// 
			// labelKeyInfo
			// 
			this->labelKeyInfo->AutoSize = true;
			this->labelKeyInfo->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->labelKeyInfo->ForeColor = System::Drawing::Color::DarkRed;
			this->labelKeyInfo->Location = System::Drawing::Point(485, 170);
			this->labelKeyInfo->Name = L"labelKeyInfo";
			this->labelKeyInfo->Size = System::Drawing::Size(157, 13);
			this->labelKeyInfo->TabIndex = 20;
			this->labelKeyInfo->Text = L"Enter key or click Generate Key";
			// 
			// radioTextKey
			// 
			this->radioTextKey->AutoSize = true;
			this->radioTextKey->Checked = true;
			this->radioTextKey->Location = System::Drawing::Point(5, 5);
			this->radioTextKey->Name = L"radioTextKey";
			this->radioTextKey->Size = System::Drawing::Size(67, 17);
			this->radioTextKey->TabIndex = 21;
			this->radioTextKey->TabStop = true;
			this->radioTextKey->Text = L"Text Key";
			this->radioTextKey->UseVisualStyleBackColor = true;
			this->radioTextKey->CheckedChanged += gcnew System::EventHandler(this, &MainForm::radioKeyType_CheckedChanged);
			// 
			// radioHexKey
			// 
			this->radioHexKey->AutoSize = true;
			this->radioHexKey->Location = System::Drawing::Point(80, 5);
			this->radioHexKey->Name = L"radioHexKey";
			this->radioHexKey->Size = System::Drawing::Size(65, 17);
			this->radioHexKey->TabIndex = 22;
			this->radioHexKey->Text = L"Hex Key";
			this->radioHexKey->UseVisualStyleBackColor = true;
			this->radioHexKey->CheckedChanged += gcnew System::EventHandler(this, &MainForm::radioKeyType_CheckedChanged);
			// 
			// panelKeyType
			// 
			this->panelKeyType->Controls->Add(this->radioHexKey);
			this->panelKeyType->Controls->Add(this->radioTextKey);
			this->panelKeyType->Location = System::Drawing::Point(170, 195);
			this->panelKeyType->Name = L"panelKeyType";
			this->panelKeyType->Size = System::Drawing::Size(150, 25);
			this->panelKeyType->TabIndex = 23;
			// 
			// panelRSAKeys
			// 
			this->panelRSAKeys->Controls->Add(this->buttonExportPrivate);
			this->panelRSAKeys->Controls->Add(this->buttonExportPublic);
			this->panelRSAKeys->Controls->Add(this->buttonImportPrivate);
			this->panelRSAKeys->Controls->Add(this->buttonImportPublic);
			this->panelRSAKeys->Controls->Add(this->buttonGenerateRSAKeys);
			this->panelRSAKeys->Controls->Add(this->label10);
			this->panelRSAKeys->Controls->Add(this->label9);
			this->panelRSAKeys->Controls->Add(this->textBoxPrivateKey);
			this->panelRSAKeys->Controls->Add(this->textBoxPublicKey);
			this->panelRSAKeys->Location = System::Drawing::Point(23, 195);
			this->panelRSAKeys->Name = L"panelRSAKeys";
			this->panelRSAKeys->Size = System::Drawing::Size(740, 100);
			this->panelRSAKeys->TabIndex = 24;
			this->panelRSAKeys->Visible = false;
			// 
			// buttonExportPrivate
			// 
			this->buttonExportPrivate->BackColor = System::Drawing::Color::LightGray;
			this->buttonExportPrivate->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonExportPrivate->Location = System::Drawing::Point(620, 74);
			this->buttonExportPrivate->Name = L"buttonExportPrivate";
			this->buttonExportPrivate->Size = System::Drawing::Size(110, 23);
			this->buttonExportPrivate->TabIndex = 32;
			this->buttonExportPrivate->Text = L"Export Private";
			this->buttonExportPrivate->UseVisualStyleBackColor = false;
			this->buttonExportPrivate->Click += gcnew System::EventHandler(this, &MainForm::buttonExportPrivate_Click);
			// 
			// buttonExportPublic
			// 
			this->buttonExportPublic->BackColor = System::Drawing::Color::LightGray;
			this->buttonExportPublic->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonExportPublic->Location = System::Drawing::Point(620, 5);
			this->buttonExportPublic->Name = L"buttonExportPublic";
			this->buttonExportPublic->Size = System::Drawing::Size(110, 23);
			this->buttonExportPublic->TabIndex = 31;
			this->buttonExportPublic->Text = L"Export Public";
			this->buttonExportPublic->UseVisualStyleBackColor = false;
			this->buttonExportPublic->Click += gcnew System::EventHandler(this, &MainForm::buttonExportPublic_Click);
			// 
			// buttonImportPrivate
			// 
			this->buttonImportPrivate->BackColor = System::Drawing::Color::LightGray;
			this->buttonImportPrivate->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonImportPrivate->Location = System::Drawing::Point(500, 74);
			this->buttonImportPrivate->Name = L"buttonImportPrivate";
			this->buttonImportPrivate->Size = System::Drawing::Size(110, 23);
			this->buttonImportPrivate->TabIndex = 30;
			this->buttonImportPrivate->Text = L"Import Private";
			this->buttonImportPrivate->UseVisualStyleBackColor = false;
			this->buttonImportPrivate->Click += gcnew System::EventHandler(this, &MainForm::buttonImportPrivate_Click);
			// 
			// buttonImportPublic
			// 
			this->buttonImportPublic->BackColor = System::Drawing::Color::LightGray;
			this->buttonImportPublic->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonImportPublic->Location = System::Drawing::Point(500, 5);
			this->buttonImportPublic->Name = L"buttonImportPublic";
			this->buttonImportPublic->Size = System::Drawing::Size(110, 23);
			this->buttonImportPublic->TabIndex = 29;
			this->buttonImportPublic->Text = L"Import Public";
			this->buttonImportPublic->UseVisualStyleBackColor = false;
			this->buttonImportPublic->Click += gcnew System::EventHandler(this, &MainForm::buttonImportPublic_Click);
			// 
			// buttonGenerateRSAKeys
			// 
			this->buttonGenerateRSAKeys->BackColor = System::Drawing::Color::LightYellow;
			this->buttonGenerateRSAKeys->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonGenerateRSAKeys->Location = System::Drawing::Point(620, 34);
			this->buttonGenerateRSAKeys->Name = L"buttonGenerateRSAKeys";
			this->buttonGenerateRSAKeys->Size = System::Drawing::Size(110, 40);
			this->buttonGenerateRSAKeys->TabIndex = 28;
			this->buttonGenerateRSAKeys->Text = L"Generate RSA Keys";
			this->buttonGenerateRSAKeys->UseVisualStyleBackColor = false;
			this->buttonGenerateRSAKeys->Click += gcnew System::EventHandler(this, &MainForm::buttonGenerateRSAKeys_Click);
			// 
			// label10
			// 
			this->label10->AutoSize = true;
			this->label10->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label10->Location = System::Drawing::Point(10, 50);
			this->label10->Name = L"label10";
			this->label10->Size = System::Drawing::Size(90, 16);
			this->label10->TabIndex = 27;
			this->label10->Text = L"Private Key:";
			// 
			// label9
			// 
			this->label9->AutoSize = true;
			this->label9->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label9->Location = System::Drawing::Point(10, 5);
			this->label9->Name = L"label9";
			this->label9->Size = System::Drawing::Size(84, 16);
			this->label9->TabIndex = 26;
			this->label9->Text = L"Public Key:";
			// 
			// textBoxPrivateKey
			// 
			this->textBoxPrivateKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->textBoxPrivateKey->Location = System::Drawing::Point(10, 70);
			this->textBoxPrivateKey->Name = L"textBoxPrivateKey";
			this->textBoxPrivateKey->Size = System::Drawing::Size(480, 21);
			this->textBoxPrivateKey->TabIndex = 25;
			// 
			// textBoxPublicKey
			// 
			this->textBoxPublicKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBoxPublicKey->Location = System::Drawing::Point(10, 25);
			this->textBoxPublicKey->Name = L"textBoxPublicKey";
			this->textBoxPublicKey->Size = System::Drawing::Size(480, 21);
			this->textBoxPublicKey->TabIndex = 24;
			// 
			// panelECCKeys
			// 
			this->panelECCKeys->Controls->Add(this->buttonExportECCPrivate);
			this->panelECCKeys->Controls->Add(this->buttonExportECCPublic);
			this->panelECCKeys->Controls->Add(this->buttonImportECCPrivate);
			this->panelECCKeys->Controls->Add(this->buttonImportECCPublic);
			this->panelECCKeys->Controls->Add(this->buttonGenerateECCKeys);
			this->panelECCKeys->Controls->Add(this->label12);
			this->panelECCKeys->Controls->Add(this->label11);
			this->panelECCKeys->Controls->Add(this->textBoxECCPrivateKey);
			this->panelECCKeys->Controls->Add(this->textBoxECCPublicKey);
			this->panelECCKeys->Location = System::Drawing::Point(23, 195);
			this->panelECCKeys->Name = L"panelECCKeys";
			this->panelECCKeys->Size = System::Drawing::Size(740, 100);
			this->panelECCKeys->TabIndex = 25;
			this->panelECCKeys->Visible = false;
			// 
			// buttonExportECCPrivate
			// 
			this->buttonExportECCPrivate->BackColor = System::Drawing::Color::LightGray;
			this->buttonExportECCPrivate->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->buttonExportECCPrivate->Location = System::Drawing::Point(620, 74);
			this->buttonExportECCPrivate->Name = L"buttonExportECCPrivate";
			this->buttonExportECCPrivate->Size = System::Drawing::Size(110, 23);
			this->buttonExportECCPrivate->TabIndex = 32;
			this->buttonExportECCPrivate->Text = L"Export Private";
			this->buttonExportECCPrivate->UseVisualStyleBackColor = false;
			this->buttonExportECCPrivate->Click += gcnew System::EventHandler(this, &MainForm::buttonExportECCPrivate_Click);
			// 
			// buttonExportECCPublic
			// 
			this->buttonExportECCPublic->BackColor = System::Drawing::Color::LightGray;
			this->buttonExportECCPublic->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->buttonExportECCPublic->Location = System::Drawing::Point(620, 5);
			this->buttonExportECCPublic->Name = L"buttonExportECCPublic";
			this->buttonExportECCPublic->Size = System::Drawing::Size(110, 23);
			this->buttonExportECCPublic->TabIndex = 31;
			this->buttonExportECCPublic->Text = L"Export Public";
			this->buttonExportECCPublic->UseVisualStyleBackColor = false;
			this->buttonExportECCPublic->Click += gcnew System::EventHandler(this, &MainForm::buttonExportECCPublic_Click);
			// 
			// buttonImportECCPrivate
			// 
			this->buttonImportECCPrivate->BackColor = System::Drawing::Color::LightGray;
			this->buttonImportECCPrivate->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->buttonImportECCPrivate->Location = System::Drawing::Point(500, 74);
			this->buttonImportECCPrivate->Name = L"buttonImportECCPrivate";
			this->buttonImportECCPrivate->Size = System::Drawing::Size(110, 23);
			this->buttonImportECCPrivate->TabIndex = 30;
			this->buttonImportECCPrivate->Text = L"Import Private";
			this->buttonImportECCPrivate->UseVisualStyleBackColor = false;
			this->buttonImportECCPrivate->Click += gcnew System::EventHandler(this, &MainForm::buttonImportECCPrivate_Click);
			// 
			// buttonImportECCPublic
			// 
			this->buttonImportECCPublic->BackColor = System::Drawing::Color::LightGray;
			this->buttonImportECCPublic->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 8.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->buttonImportECCPublic->Location = System::Drawing::Point(500, 5);
			this->buttonImportECCPublic->Name = L"buttonImportECCPublic";
			this->buttonImportECCPublic->Size = System::Drawing::Size(110, 23);
			this->buttonImportECCPublic->TabIndex = 29;
			this->buttonImportECCPublic->Text = L"Import Public";
			this->buttonImportECCPublic->UseVisualStyleBackColor = false;
			this->buttonImportECCPublic->Click += gcnew System::EventHandler(this, &MainForm::buttonImportECCPublic_Click);
			// 
			// buttonGenerateECCKeys
			// 
			this->buttonGenerateECCKeys->BackColor = System::Drawing::Color::LightYellow;
			this->buttonGenerateECCKeys->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->buttonGenerateECCKeys->Location = System::Drawing::Point(620, 34);
			this->buttonGenerateECCKeys->Name = L"buttonGenerateECCKeys";
			this->buttonGenerateECCKeys->Size = System::Drawing::Size(110, 40);
			this->buttonGenerateECCKeys->TabIndex = 28;
			this->buttonGenerateECCKeys->Text = L"Generate ECC Keys";
			this->buttonGenerateECCKeys->UseVisualStyleBackColor = false;
			this->buttonGenerateECCKeys->Click += gcnew System::EventHandler(this, &MainForm::buttonGenerateECCKeys_Click);
			// 
			// label12
			// 
			this->label12->AutoSize = true;
			this->label12->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label12->Location = System::Drawing::Point(10, 50);
			this->label12->Name = L"label12";
			this->label12->Size = System::Drawing::Size(90, 16);
			this->label12->TabIndex = 27;
			this->label12->Text = L"Private Key:";
			// 
			// label11
			// 
			this->label11->AutoSize = true;
			this->label11->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label11->Location = System::Drawing::Point(10, 5);
			this->label11->Name = L"label11";
			this->label11->Size = System::Drawing::Size(84, 16);
			this->label11->TabIndex = 26;
			this->label11->Text = L"Public Key:";
			// 
			// textBoxECCPrivateKey
			// 
			this->textBoxECCPrivateKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->textBoxECCPrivateKey->Location = System::Drawing::Point(10, 70);
			this->textBoxECCPrivateKey->Name = L"textBoxECCPrivateKey";
			this->textBoxECCPrivateKey->Size = System::Drawing::Size(480, 21);
			this->textBoxECCPrivateKey->TabIndex = 25;
			// 
			// textBoxECCPublicKey
			// 
			this->textBoxECCPublicKey->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.1F, System::Drawing::FontStyle::Regular,
				System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->textBoxECCPublicKey->Location = System::Drawing::Point(10, 25);
			this->textBoxECCPublicKey->Name = L"textBoxECCPublicKey";
			this->textBoxECCPublicKey->Size = System::Drawing::Size(480, 21);
			this->textBoxECCPublicKey->TabIndex = 24;
			// 
			// MainForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(784, 661);
			this->Controls->Add(this->panelECCKeys);
			this->Controls->Add(this->panelRSAKeys);
			this->Controls->Add(this->panelKeyType);
			this->Controls->Add(this->labelKeyInfo);
			this->Controls->Add(this->buttonGenerateKey);
			this->Controls->Add(this->label8);
			this->Controls->Add(this->textBoxKey);
			this->Controls->Add(this->richTextBox1);
			this->Controls->Add(this->label7);
			this->Controls->Add(this->button5);
			this->Controls->Add(this->button4);
			this->Controls->Add(this->button3);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->comboBox1);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->label1);
			this->Name = L"MainForm";
			this->Text = L"Advanced Encryption Tool";
			this->panelKeyType->ResumeLayout(false);
			this->panelKeyType->PerformLayout();
			this->panelRSAKeys->ResumeLayout(false);
			this->panelRSAKeys->PerformLayout();
			this->panelECCKeys->ResumeLayout(false);
			this->panelECCKeys->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

	private:
		// Event Handlers
		void button1_Click(System::Object^ sender, System::EventArgs^ e);
		void button2_Click(System::Object^ sender, System::EventArgs^ e);
		void button3_Click(System::Object^ sender, System::EventArgs^ e);
		void button4_Click(System::Object^ sender, System::EventArgs^ e);
		void button5_Click(System::Object^ sender, System::EventArgs^ e);
		void comboBox1_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e);
		void textBoxKey_TextChanged(System::Object^ sender, System::EventArgs^ e);
		void buttonGenerateKey_Click(System::Object^ sender, System::EventArgs^ e);
		void radioKeyType_CheckedChanged(System::Object^ sender, System::EventArgs^ e);
		void buttonGenerateRSAKeys_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonImportPublic_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonImportPrivate_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonExportPublic_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonExportPrivate_Click(System::Object^ sender, System::EventArgs^ e);

		// ECC Event Handlers
		void buttonGenerateECCKeys_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonImportECCPublic_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonImportECCPrivate_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonExportECCPublic_Click(System::Object^ sender, System::EventArgs^ e);
		void buttonExportECCPrivate_Click(System::Object^ sender, System::EventArgs^ e);

		// Core Encryption Methods
		void InitializeEncryption();
		String^ GenerateRandomKey(int size);
		String^ GenerateRandomIV(int size);
		void UpdateKeyInfo();
		bool ValidateKeySize(String^ algorithm, array<Byte>^ keyBytes);
		String^ GetKeySizeInfo(String^ algorithm, array<Byte>^ keyBytes);
		array<Byte>^ GetKeyBytesFromInput();
		String^ EncryptString(String^ plainText, String^ algorithm);
		String^ DecryptString(String^ cipherText, String^ algorithm);
		bool EncryptFile(String^ inputFile, String^ outputFile, String^ algorithm);
		bool DecryptFile(String^ inputFile, String^ outputFile, String^ algorithm);

		// Custom RSA Implementation
		ref struct RSAKeyPair
		{
			BigInteger n;	// Modulus
			BigInteger e;	// Public exponent
			BigInteger d;	// Private exponent
			BigInteger p;	// Prime p
			BigInteger q;	// Prime q
		};

		RSAKeyPair^ currentRSAKeyPair;
		RSAKeyPair^ GenerateRSAKeyPair(int keySize);
		array<Byte>^ RSA_Encrypt(array<Byte>^ data, BigInteger n, BigInteger e);
		array<Byte>^ RSA_Decrypt(array<Byte>^ data, BigInteger n, BigInteger d);
		bool IsPrime(BigInteger n, int k);
		BigInteger GenerateRandomPrime(int bits);
		BigInteger ModularInverse(BigInteger a, BigInteger m);
		BigInteger ModularPow(BigInteger base, BigInteger exponent, BigInteger modulus);

		// PEM Format Support
		String^ ExportPublicKeyToPEM(BigInteger n, BigInteger e);
		String^ ExportPrivateKeyToPEM(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q);
		bool ImportPublicKeyFromPEM(String^ pem, BigInteger% n, BigInteger% e);
		bool ImportPrivateKeyFromPEM(String^ pem, BigInteger% n, BigInteger% e, BigInteger% d, BigInteger% p, BigInteger% q);
		array<Byte>^ DecodePEM(String^ pem);
		String^ EncodePEM(String^ label, array<Byte>^ data);
		array<Byte>^ EncodeDERSequence(List<array<Byte>^>^ elements);
		array<Byte>^ EncodeDERInteger(BigInteger value);
		BigInteger DecodeDERInteger(array<Byte>^ der);
		List<array<Byte>^>^ ParseDERSequence(array<Byte>^ der);
		bool IsValidText(String^ text);

		// Custom ECC P-256 Implementation
		ref struct ECCPoint
		{
			BigInteger x;
			BigInteger y;
			bool isInfinity;

			ECCPoint()
			{
				x = BigInteger::Zero;
				y = BigInteger::Zero;
				isInfinity = true;
			}

			ECCPoint(BigInteger x_val, BigInteger y_val)
			{
				x = x_val;
				y = y_val;
				isInfinity = false;
			}
		};

		ref struct ECCKeyPair
		{
			BigInteger privateKey;			// d (private key)
			ECCPoint^ publicKey;			// Q = d * G (public key)
		};

		// ECC P-256 curve parameters (NIST P-256 / secp256r1)
		BigInteger p;						// Prime modulus
		BigInteger a;						// Curve parameter a
		BigInteger b;						// Curve parameter b
		BigInteger n;						// Order of base point
		ECCPoint^ G;						// Base point
		ECCKeyPair^ currentECCKeyPair;

		void InitializeECC_P256();
		ECCKeyPair^ GenerateECCKeyPair();
		ECCPoint^ ECC_PointAdd(ECCPoint^ P, ECCPoint^ Q);
		ECCPoint^ ECC_PointDouble(ECCPoint^ P);
		ECCPoint^ ECC_ScalarMultiply(BigInteger k, ECCPoint^ P);
		bool ECC_PointOnCurve(ECCPoint^ P);
		BigInteger ECC_ModInverse(BigInteger a);
		BigInteger ECC_Mod(BigInteger value);
		BigInteger ECC_ModAdd(BigInteger a, BigInteger b);
		BigInteger ECC_ModSub(BigInteger a, BigInteger b);
		BigInteger ECC_ModMul(BigInteger a, BigInteger b);
		BigInteger ECC_ModSquare(BigInteger a);
		BigInteger GenerateRandomPrivateKey();
		array<Byte>^ ECC_Encrypt(array<Byte>^ data, ECCPoint^ publicKey);
		array<Byte>^ ECC_Decrypt(array<Byte>^ data, BigInteger privateKey);
		String^ ExportECCPublicKeyToPEM(ECCPoint^ publicKey);
		String^ ExportECCPrivateKeyToPEM(BigInteger privateKey);
		bool ImportECCPublicKeyFromPEM(String^ pem, ECCPoint^% publicKey);
		bool ImportECCPrivateKeyFromPEM(String^ pem, BigInteger% privateKey);
		String^ ECCPointToBase64(ECCPoint^ point);
		ECCPoint^ Base64ToECCPoint(String^ base64);
		BigInteger Base64ToBigInteger(String^ base64);
		String^ BigIntegerToBase64(BigInteger value);

		// Custom AES Implementation
		array<Byte>^ AES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);
		array<Byte>^ AES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);

		// AES Helper Methods
		UInt32 AES_SubWord(UInt32 word);
		UInt32 AES_RotWord(UInt32 word);
		void AES_KeyExpansion(array<Byte>^ key, array<UInt32>^ w);
		void AES_AddRoundKey(array<UInt32>^ state, array<UInt32>^ w, int round);
		void AES_SubBytes(array<UInt32>^ state);
		void AES_InvSubBytes(array<UInt32>^ state);
		void AES_ShiftRows(array<UInt32>^ state);
		void AES_InvShiftRows(array<UInt32>^ state);
		Byte AES_GFMultiply(Byte a, Byte b);
		void AES_MixColumns(array<UInt32>^ state);
		void AES_InvMixColumns(array<UInt32>^ state);

		// Custom 3DES Implementation
		array<Byte>^ TripleDES_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);
		array<Byte>^ TripleDES_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);

		// 3DES Helper Methods
		UInt64 DES_Permute(UInt64 data, array<Byte>^ table, int inputSize);
		void DES_GenerateSubkeys(UInt64 key, array<UInt64>^ subkeys);
		UInt32 DES_Function(UInt32 right, UInt64 subkey);
		UInt64 DES_ProcessBlock(UInt64 block, array<UInt64>^ subkeys, bool encrypt);

		// Other Algorithm Implementations
		array<Byte>^ RC4_Encrypt(array<Byte>^ data, array<Byte>^ key);
		array<Byte>^ RC4_Decrypt(array<Byte>^ data, array<Byte>^ key);
		array<Byte>^ ChaCha20_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce);
		array<Byte>^ ChaCha20_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ nonce);
		array<Byte>^ Blowfish_Encrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);
		array<Byte>^ Blowfish_Decrypt(array<Byte>^ data, array<Byte>^ key, array<Byte>^ iv);

		// Blowfish specific methods
		void InitializeBlowfish(array<Byte>^ key);
		UInt32 F(UInt32 x);
		void EncryptBlock(array<UInt32>^ block);
		void DecryptBlock(array<UInt32>^ block);

		// ChaCha20 Helper
		UInt32 RotateLeft(UInt32 value, int offset);
		void QuarterRound(array<UInt32>^ state, int a, int b, int c, int d);

		// AES Constants
		static array<UInt32>^ GetAES_RCON() {
			return gcnew array<UInt32> {
				0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
					0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
			};
		}

		static array<Byte>^ GetAES_SBOX() {
			return gcnew array<Byte> {
				0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
					0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
					0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
					0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
					0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
					0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
					0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
					0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
					0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
					0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
					0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
					0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
					0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
					0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
					0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
					0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
			};
		}

		static array<Byte>^ GetAES_INV_SBOX() {
			return gcnew array<Byte> {
				0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
					0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
					0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
					0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
					0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
					0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
					0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
					0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
					0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
					0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
					0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
					0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
					0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
					0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
					0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
					0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
			};
		}

		// 3DES Constants
		static array<Byte>^ GetDES_IP() {
			return gcnew array<Byte> {
				58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
					62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
					57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
					61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
			};
		}

		static array<Byte>^ GetDES_FP() {
			return gcnew array<Byte> {
				40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
					38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
					36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
					34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
			};
		}

		static array<Byte>^ GetDES_PC1() {
			return gcnew array<Byte> {
				57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
					10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
					63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
					14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
			};
		}

		static array<Byte>^ GetDES_PC2() {
			return gcnew array<Byte> {
				14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
					23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
					41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
					44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
			};
		}

		static array<Byte>^ GetDES_E() {
			return gcnew array<Byte> {
				32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
					8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
					24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
			};
		}

		static array<Byte>^ GetDES_P() {
			return gcnew array<Byte> {
				16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
					2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
			};
		}

		static array<Byte>^ GetDES_SHIFTS() {
			return gcnew array<Byte> { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
		}

		static array<array<Byte>^>^ GetDES_SBOX() {
			array<array<Byte>^>^ sboxes = gcnew array<array<Byte>^>(8);

			// S1
			sboxes[0] = gcnew array<Byte> {
				14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
					0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
					4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
					15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
			};
			// S2
			sboxes[1] = gcnew array<Byte> {
				15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
					3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
					0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
					13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
			};
			// S3
			sboxes[2] = gcnew array<Byte> {
				10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
					13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
					13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
					1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
			};
			// S4
			sboxes[3] = gcnew array<Byte> {
				7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
					13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
					10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
					3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
			};
			// S5
			sboxes[4] = gcnew array<Byte> {
				2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
					14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
					4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
					11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
			};
			// S6
			sboxes[5] = gcnew array<Byte> {
				12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
					10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
					9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
					4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
			};
			// S7
			sboxes[6] = gcnew array<Byte> {
				4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
					13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
					1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
					6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
			};
			// S8
			sboxes[7] = gcnew array<Byte> {
				13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
					1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
					7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
					2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
			};

			return sboxes;
		}

		// Blowfish constants
		static array<UInt32>^ GetP_INIT() {
			return gcnew array<UInt32> {
				0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
					0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
					0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
			};
		}

		static array<UInt32>^ GetS_INIT() {
			return gcnew array<UInt32> {
				// S-box 1
				0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
					0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16,
					0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658,
					0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013,
					0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
					0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60,
					0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
					0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A,
					0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C,
					0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
					0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
					0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
					0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
					0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
					0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
					0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE,
					0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
					0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B,
					0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B,
					0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463,
					0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C,
					0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3,
					0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD, 0x1A60320A,
					0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8,
					0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760,
					0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB,
					0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8,
					0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B,
					0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33,
					0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4,
					0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0,
					0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C,
					0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777,
					0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299,
					0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9, 0x165FA266, 0x80957705,
					0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF,
					0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D, 0x2071B35E,
					0x226800BB, 0x57B8E0AF, 0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA,
					0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376, 0x6295CFA9,
					0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915,
					0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400, 0x08BA6FB5, 0x571BE91F,
					0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664,
					0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A,
					// S-box 2
					0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0, 0x49A7DF7D,
					0x9CEE60B8, 0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1,
					0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65,
					0x6B8FE4D6, 0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1,
					0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9,
					0x3C971814, 0x6B6A70A1, 0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737,
					0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37, 0xF0500C0D,
					0xF01C1F04, 0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD,
					0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC,
					0xC8B57634, 0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41,
					0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908,
					0x6F420D03, 0xF60A04BF, 0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF,
					0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F, 0x2E6B7124,
					0x501ADDE6, 0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C,
					0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908,
					0xDD433B37, 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD,
					0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B,
					0x3C11183B, 0x5924A509, 0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E,
					0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C, 0x4E3D06FA,
					0x2965DCB9, 0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A,
					0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D,
					0x1939260F, 0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66,
					0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5,
					0x65582185, 0x68AB9802, 0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84,
					0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830, 0xEB61BD96,
					0x0334FE1E, 0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14,
					0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA,
					0xA02369B9, 0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7,
					0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77,
					0x11ED935F, 0x16681281, 0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99,
					0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696, 0xCDB30AEB, 0x532E3054,
					0x8FD948E4, 0x6DBC3128, 0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73,
					0x5D4A14D9, 0xE864B7E3, 0x42105D14, 0x203E13E0, 0x45EEE2B6, 0xA3AAABEA,
					0xDB6C4F15, 0xFACB4FD0, 0xC742F442, 0xEF6ABBB5, 0x654F3B1D, 0x41CD2105,
					0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250, 0xCF62A1F2, 0x5B8D2646,
					0xFC8883A0, 0xC1C7B6A3, 0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285,
					0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00, 0x58428D2A, 0x0C55F5EA,
					0x1DADF43E, 0x233F7061, 0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB,
					0x7CDE3759, 0xCBEE7460, 0x4085F2A7, 0xCE77326E, 0xA6078084, 0x19F8509E,
					0xE8EFD855, 0x61D99735, 0xA969A7AA, 0xC50C06C2, 0x5A04ABFC, 0x800BCADC,
					0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9, 0xDB73DBD3, 0x105588CD,
					0x675FDA79, 0xE3674340, 0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20,
					0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7,
					// S-box 3
					0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934, 0x411520F7, 0x7602D4F7,
					0xBCF46B2E, 0xD4A20068, 0xD4082471, 0x3320F46A, 0x43B7D4B7, 0x500061AF,
					0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840, 0x4D95FC1D, 0x96B591AF,
					0x70F4DDD3, 0x66A02F45, 0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504,
					0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A, 0x28507825, 0x530429F4,
					0x0A2C86DA, 0xE9B66DFB, 0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE,
					0x4F3FFEA2, 0xE887AD8C, 0xB58CE006, 0x7AF4D6B6, 0xAACE1E7C, 0xD3375FEC,
					0xCE78A399, 0x406B2A42, 0x20FE9E35, 0xD9F385B9, 0xEE39D7AB, 0x3B124E8B,
					0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2, 0x3A6EFA74, 0xDD5B4332,
					0x6841E7F7, 0xCA7820FB, 0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527,
					0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B, 0x55A867BC, 0xA1159A58,
					0xCCA92963, 0x99E1DB33, 0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C,
					0xFDF8E802, 0x04272F70, 0x80BB155C, 0x05282CE3, 0x95C11548, 0xE4C66D22,
					0x48C1133F, 0xC70F86DC, 0x07F9C9EE, 0x41041F0F, 0x404779A4, 0x5D886E17,
					0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564, 0x257B7834, 0x602A9C60,
					0xDFF8E8A3, 0x1F636C1B, 0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115,
					0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922, 0x85B2A20E, 0xE6BA0D99,
					0xDE720C8C, 0x2DA2F728, 0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0,
					0x5449A36F, 0x877D48FA, 0xC39DFD27, 0xF33E8D1E, 0x0A476341, 0x992EFF74,
					0x3A6F6EAB, 0xF4F8FD37, 0xA812DC60, 0xA1EBDDF8, 0x991BE14C, 0xDB6E6B0D,
					0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804, 0xF1290DC7, 0xCC00FFA3,
					0xB5390F92, 0x690FED0B, 0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3,
					0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB, 0x37392EB3, 0xCC115979,
					0x8026E297, 0xF42E312D, 0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C,
					0x6A124237, 0xB79251E7, 0x06A1BBE6, 0x4BFB6350, 0x1A6B1018, 0x11CAEDFA,
					0x3D25BDD8, 0xE2E1C3C9, 0x44421659, 0x0A121386, 0xD90CEC6E, 0xD5ABEA2A,
					0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE, 0x9DBC8057, 0xF0F7C086,
					0x60787BF8, 0x6003604D, 0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC,
					0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F, 0x77A057BE, 0xBDE8AE24,
					0x55464299, 0xBF582E61, 0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2,
					0x5366F9C3, 0xC8B38E74, 0xB475F255, 0x46FCD9B9, 0x7AEB2661, 0x8B1DDF84,
					0x846A0E79, 0x915F95E2, 0x466E598E, 0x20B45770, 0x8CD55591, 0xC902DE4C,
					0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E, 0xB77F19B6, 0xE0A9DC09,
					0x662D09A1, 0xC4324633, 0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10,
					0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169, 0xDCB7DA83, 0x573906FE,
					0xA1E2CE9B, 0x4FCD7F52, 0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027,
					0x9AF88C27, 0x773F8641, 0xC3604C06, 0x61A806B5, 0xF0177A28, 0xC0F586E0,
					0x006058AA, 0x30DC7D62, 0x11E69ED7, 0x2338EA63, 0x53C2DD94, 0xC2C21634,
					0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76, 0x6F05E409, 0x4B7C0188,
					0x39720A3D, 0x7C927C24, 0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC,
					0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4, 0x1E50EF5E, 0xB161E6F8,
					0xA28514D9, 0x6C51133C, 0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837,
					0xD79A3234, 0x92638212, 0x670EFA8E, 0x406000E0,
					// S-box 4
					0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B, 0x5CB0679E, 0x4FA33742,
					0xD3822740, 0x99BC9BBE, 0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B,
					0xB78C1B6E, 0x21A19045, 0xB26EB1BE, 0x6A366EB4, 0x5748AB2F, 0xBC946E79,
					0xC6A376D2, 0x6549C2C8, 0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6,
					0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304, 0xA1FAD5F0, 0x6A2D519A,
					0x63EF8CE2, 0x9A86EE22, 0xC089C2B8, 0x43242EF6, 0xA51E03AA, 0x9CF2D0A4,
					0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6, 0x2826A2F9, 0xA73A3AE1,
					0x4BA99586, 0xEF5562E9, 0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59,
					0x80E4A915, 0x87B08601, 0x9B09E6AD, 0x3B3EE593, 0xE990FD5A, 0x9E34D797,
					0x2CF0B7D9, 0x022B8B51, 0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28,
					0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C, 0xE029AC71, 0xE019A5E6,
					0x47B0ACFD, 0xED93FA9B, 0xE8D3C48D, 0x283B57CC, 0xF8D56629, 0x79132E28,
					0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C, 0x15056DD4, 0x88F46DBA,
					0x03A16125, 0x0564F0BD, 0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A,
					0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB, 0x26DCF319, 0x7533D928, 0xB155FDF5,
					0x03563482, 0x8ABA3CBB, 0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F,
					0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991, 0xEA7A90C2, 0xFB3E7BCE,
					0x5121CE64, 0x774FBE32, 0xA8B6E37E, 0xC3293D46, 0x48DE5369, 0x6413E680,
					0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166, 0xB39A460A, 0x6445C0DD,
					0x586CDECF, 0x1C20C8AE, 0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB,
					0xDDA26A7E, 0x3A59FF45, 0x3E350A44, 0xBCB4CDD5, 0x72EACEA8, 0xFA6484BB,
					0x8D6612AE, 0xBF3C6F47, 0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370,
					0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D, 0x4040CB08, 0x4EB4E2CC,
					0x34D2466A, 0x0115AF84, 0xE1B00428, 0x95983A1D, 0x06B89FB4, 0xCE6EA048,
					0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8, 0x611560B1, 0xE7933FDC,
					0xBB3A792B, 0x344525BD, 0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9,
					0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3, 0xA1E8AAC7, 0x1A908749, 0xD44FBD9A,
					0xD0DADECB, 0xD50ADA38, 0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F,
					0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C, 0xBF97222C, 0x15E6FC2A,
					0x0F91FC71, 0x9B941525, 0xFAE59361, 0xCEB69CEB, 0xC2A86459, 0x12BAA8D1,
					0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442, 0xE0EC6E0E, 0x1698DB3B,
					0x4C98A0BE, 0x3278E964, 0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E,
					0x1B0A7441, 0x4BA3348C, 0xC5BE7120, 0xC37632D8, 0xDF359F8D, 0x9B992F2E,
					0xE60B6F47, 0x0FE3F11D, 0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F,
					0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299, 0xF523F357, 0xA6327623,
					0x93A83531, 0x56CCCD02, 0xACF08162, 0x5A75EBB5, 0x6E163697, 0x88D273CC,
					0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614, 0xE6C6C7BD, 0x327A140A,
					0x45E1D006, 0xC3F27B9A, 0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6,
					0x71126905, 0xB2040222, 0xB6CBCF7C, 0xCD769C2B, 0x53113EC0, 0x1640E3D3,
					0x38ABBD60, 0x2547ADF0, 0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060,
					0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E, 0x1948C25C, 0x02FB8A8C,
					0x01C36AE4, 0xD6EBE1F9, 0x90D4F869, 0xA65CDEA0, 0x3F09252D, 0xC208E69F,
					0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6
			};
		}

		// Blowfish state arrays
		array<UInt32>^ P;
		array<array<UInt32>^>^ S;
		bool ParsePublicKeyDER(array<Byte>^ der, BigInteger% n, BigInteger% e);
		bool ParsePrivateKeyDER(array<Byte>^ der, BigInteger% n, BigInteger% e, BigInteger% d, BigInteger% p, BigInteger% q);

	};
}