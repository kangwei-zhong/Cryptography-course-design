#include "DES.h"
#include <string>
using namespace std;

string hexasctostr(string input){
	string res;
	for(int i = 0; i + 1 < input.size(); i +=2){
		if(input[i] >= 'a' && input[i+1] >= 'a'){
		 	res += char((input[i] - 'a' + 10)*16 + input[i+1] - 'a'+ 10);
		}
		else if(input[i] >= 'a' && input[i+1] < 'a'){
			res += char((input[i] - 'a' + 10)*16 + input[i+1] - '0');
		}
		else if(input[i] < 'a' && input[i+1] >= 'a'){
			res += char((input[i] - '0' )*16 + input[i+1] - 'a'+ 10);
		}
		else{
			res += char((input[i] - '0')*16 + input[i+1] - '0');
		}
	}
	return res;
}

int main(void)
{
	string plain="All these things have you said of beauty, yet in truth you spoke not of her but of needs unsatisfied, and beauty is not a need but an ecstasy. It is not a mouth thirsting nor an empty hand stretched forth, but rather a heart enflamed and a soul enchanted. It is not the image you would see nor the song you would hear, but rather an image you see though you close your eyes and a song you hear though you shut your ears. It is not the sap within the furrowed bark, nor a wing attached to a claw, but rather a garden for ever in bloom and a flock of angels for ever in flight.";
	cout << "The message is :" << plain << endl; 
	string key="abcdefgh";    
	string v="abcdefgh";
	string cipher0,cipher1, cipher2, cipher3, cipher4;
	string plain0, plain1, plain2, plain3, plain4; 
	
	op_mode mode0=op_mode("ECB");
	op_mode mode1=op_mode("CBC");
	op_mode mode2=op_mode("CFB");
	op_mode mode3=op_mode("OFB");
	op_mode mode4=op_mode("CTR");
	clock_t startT = clock();
	cout<<"************************Encryption************************" << endl;
	cipher0=mode0.mode_enc(plain, key, v, "bin");
	clock_t endT = clock();
	double endtime0 = (double)(endT - startT) / CLOCKS_PER_SEC;
	cout<<"ECB mode cipher:"<<cipher0<<endl;
	cout<<"************************Decryption************************" << endl;
	plain0=mode0.mode_dec(cipher0, key, v, "hex");
	cout<<"ECB mode decrypted_plain:"<<hexasctostr(plain0)<<endl;
	cout<<endl;
	startT = clock();
	cout<<"************************Encryption************************" << endl;
	cipher1=mode1.mode_enc(plain, key, v, "bin");
	endT = clock();
	double endtime1 = (double)(endT - startT) / CLOCKS_PER_SEC;
	cout<<"CBC mode cipher:"<<cipher1<<endl;
	cout<<"************************Decryption************************" << endl;
	plain1=mode1.mode_dec(cipher1, key, v, "hex");
	cout<<"CBC mode decrypted_plain:"<<hexasctostr(plain1)<<endl;
	cout<<endl;
	startT = clock();
	cout<<"************************Encryption************************" << endl;
	cipher2=mode2.mode_enc(plain, key, v, "bin");
	endT = clock();
	double endtime2 = (double)(endT - startT) / CLOCKS_PER_SEC;
	cout<<"CFB mode cipher:"<<cipher2<<endl;
	cout<<"************************Decryption************************" << endl;
	plain2=mode2.mode_dec(cipher2, key, v, "hex");
	cout<<"CFB mode decrypted_plain:"<<hexasctostr(plain2)<<endl;
	cout<<endl;
	startT = clock();
	cout<<"************************Encryption************************" << endl;
	cipher3=mode3.mode_enc(plain, key, v, "bin");
	endT = clock();
	double endtime3 = (double)(endT - startT) / CLOCKS_PER_SEC;
	cout<<"OFB mode cipher:"<<cipher3<<endl;
	cout<<"************************Decryption************************" << endl;
	plain3=mode3.mode_dec(cipher3, key, v, "hex");
	cout<<"OFB mode decrypted_plain:"<<hexasctostr(plain3)<<endl;
	cout<<endl;
	startT = clock();
	cout<<"************************Encryption************************" << endl;
	cipher4=mode4.mode_enc(plain, key, v, "bin");
	endT = clock();
	double endtime4 = (double)(endT - startT) / CLOCKS_PER_SEC;
	cout<<"CTR mode cipher:"<<cipher4<<endl;
	cout<<"************************Decryption************************" << endl;
	plain4=mode4.mode_dec(cipher4, key, v, "hex");
	cout<<"CTR mode decrypted_plain:"<<hexasctostr(plain4)<<endl;
	cout<<endl;
	cout<<"*****************Performance Analysis*********************" << endl;
	cout<<"ECB mode operating time:"<< endtime0 << "s"<< endl;
	cout<<"CBC mode operating time:"<< endtime1 << "s"<< endl;
	cout<<"CFB mode operating time:"<< endtime2 << "s"<< endl;
	cout<<"OFB mode operating time:"<< endtime3 << "s"<< endl;
	cout<<"CTR mode operating time:"<< endtime4 << "s"<< endl;
	system("pause");
}
