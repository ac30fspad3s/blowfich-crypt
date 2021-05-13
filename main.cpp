#define _CRT_SECURE_NO_WARNINGS

#include "cryptopp564\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "iostream"
using namespace std;

#include "cryptopp564\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;
#include "cryptopp564\modes.h"
using CryptoPP::CBC_Mode;
#include "cryptopp564\blowfish.h"
using CryptoPP::Blowfish;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
#include "cryptopp564\modes.h"
#include "cryptopp564\files.h"
#include <fstream>
#include <string>


int main(int argc, char* argv[]) {
	if (argc == 1) {
		return 0;
	}
	
		string arg1 = argv[1];
		
		if(arg1 == "-c") 
		{
	
			string ofilename = argv[2];
			string efilename = "cryptfile"; 
			AutoSeededRandomPool rng(true);
			byte key[Blowfish::DEFAULT_KEYLENGTH];
			byte iv[Blowfish::BLOCKSIZE];

			
			rng.GenerateBlock(key, sizeof(key)); rng.GenerateBlock(iv, sizeof(iv));
			
		
			int file_name_index = ofilename.find_last_of("\\");
			string namefile = ofilename.substr(file_name_index + 1, ofilename.size());
			//namefile.c_str();

			FILE* f;
			f = fopen("key", "wb");
			fwrite(&key, sizeof(key), 1, f);
			fwrite(&iv, sizeof(iv), 1, f);
			fwrite(&namefile, sizeof(namefile), 1, f);
			fclose(f);
	
			CBC_Mode<Blowfish>::Encryption Encryptor(key, sizeof(key), iv);
			CryptoPP::FileSource fs1(ofilename.c_str(), true,
				new StreamTransformationFilter(Encryptor, new CryptoPP::FileSink(efilename.c_str())));
		}

		if (arg1 == "-e")
		{
			string efilename = argv[2];
			string key_path = argv[3];
			string rfilename;

			byte key[Blowfish::DEFAULT_KEYLENGTH];
			byte iv[Blowfish::BLOCKSIZE];
			
			FILE* f;
			f = fopen(argv[3], "rb");
			fread(&key, sizeof(key), 1, f);
			fread(&iv, sizeof(iv), 1, f);
			fread(&rfilename, sizeof(rfilename), 1, f);
			fclose(f);
			
			CBC_Mode<Blowfish>::Decryption Decryptor(key, sizeof(key), iv);
			CryptoPP::FileSource fs2(efilename.c_str(), true,
				new StreamTransformationFilter(Decryptor, new CryptoPP::FileSink(rfilename.c_str())));


		}

	
	
	return 0;
}