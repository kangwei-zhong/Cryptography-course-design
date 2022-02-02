#include <iostream>
#include <iomanip>
#include <string.h>
#include <utility>
#include <map>
#define PLAIN_SIZE 64
#define Input_EXT 48
#define KEY_SIZE 56
using namespace std;

class DES_System{
    public:
    string Encryption(string input, string scale_in, string scale_out);	
    string Decryption(string input, string scale_in, string scale_out);
    void KeyGen(string key, string scale);		//��Կ���� 
    string key2str(string scale);				//��Կת��Ϊ�ַ��� 
    private:
    int plain_mes[64], enc_mes[64], key_cur[64];	//�洢64bit�����ģ����ģ���Կ 
    string Bi2Hex(string input);				//������תʮ�����ƺ��� 
    string Hex2Bi(string input);				//ʮ������ת�����ƺ��� 
    void Ini_Permu(int input[], int output[]);	//��ʼ�û� 
    void E_extension(int input[], int output[]);	//E��չ 
    void Re_Ini_Permu(int input[], int output[]);	//���ʼ�û� 
    void LeftShift(int key[], int num);				//ѭ������ 
    void SubKeyGen(int round_num, int input[], int output[]);		//����Կ���� 
    void Sbox_Permu(int input[], int output[]);		//S���û� 
    void P_Permu(int input[], int output[]);		//P�û� 
    void Round_Permu(int linput[], int rinput[], int loutput[], int routput[], int round_key[]);	//���û� 
    void En(int input[], int output[], int key[]);
    void De(int input[], int output[], int key[]);
};


string DES_System::Encryption(string input, string scale_in, string scale_out){
    if(scale_in=="hex"){
        input = Hex2Bi(input);
    }
    for(int i = 0; i < input.size(); i++){	//��Ҫ���ܵ�����ת��Ϊ���ִ������������� 
        plain_mes[i] = input[i] - '0';	
    }
    En(plain_mes, enc_mes, key_cur);		//���ļ��� 
    string output;
    for(int i = 0; i < PLAIN_SIZE; i++){
        output.push_back(enc_mes[i]+'0');	//�õ�������ת��Ϊ�ַ��� 
    }
    if(scale_out=="hex"){
        output = Bi2Hex(output);
    }
    return output;
}

string DES_System::Decryption(string input, string scale_in, string scale_out){
    if(scale_in=="hex"){
        input = Hex2Bi(input);
    }
    for(int i = 0; i < input.size(); i++){	//������ת��Ϊ���֣�����洢������ 
        enc_mes[i] = input[i] - '0';
    }
    De(enc_mes, plain_mes, key_cur);  		//�������ģ����ܵõ����� 
    string output;
    for(int i = 0; i < PLAIN_SIZE; i++){	//���õ������Ĵ�����ת��Ϊ�ַ���������� 
        output.push_back(plain_mes[i]+'0');
    }
    if(scale_out=="hex"){
        output = Bi2Hex(output);
    }
    return output;
}

void DES_System::KeyGen(string key, string scale){
    if(scale == "hex"){
        key = Hex2Bi(key);
    }
    for(int i = 0; i < key.size(); i ++){			//����Կת��Ϊ���ִ��������� 
        key_cur[i] = key[i] - '0'; 
    }
}

string DES_System::key2str(string scale){
    string key;
    for(int i = 0; i < KEY_SIZE; i ++){  
        key.push_back(key_cur[i]+'0');
    }
    return key;
}

string DES_System::Hex2Bi(string input){
    map<char, string> trans;
    trans['0'] = "0000";
    trans['1'] = "0001";
    trans['2'] = "0010";
    trans['3'] = "0011";
    trans['4'] = "0100";
    trans['5'] = "0101";
    trans['6'] = "0110";
    trans['7'] = "0111";
    trans['8'] = "1000";
    trans['9'] = "1001";
    trans['a'] = "1010";
    trans['b'] = "1011";
    trans['c'] = "1100";
    trans['d'] = "1101";
    trans['e'] = "1110";
    trans['f'] = "1111";
    string output;
    for(int i = 0; i < input.size(); i ++){
        output+=trans[input[i]];
    }
    return output;
}

string DES_System::Bi2Hex(string input){
    map<string, string> rev;
    rev["0000"] = "0";
    rev["0001"] = "1";
    rev["0010"] = "2";
    rev["0011"] = "3";
    rev["0100"] = "4";
    rev["0101"] = "5";
    rev["0110"] = "6";
    rev["0111"] = "7";
    rev["1000"] = "8";
    rev["1001"] = "9";
    rev["1010"] = "a";
    rev["1011"] = "b";
    rev["1100"] = "c";
    rev["1101"] = "d";
    rev["1110"] = "e";
    rev["1111"] = "f";
    string output;
    for(int i = 0; i < input.size()/4; i ++){
        string s;
        for(int k = i*4; k < (i+1)*4; k ++){
            s.push_back(input[k]);
        }
        output+=rev[s];
    }
    return output;
}

void DES_System::Ini_Permu(int input[], int output[]){
    // ��ʼIP�û� 
    int IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    for(int i = 0; i < 64; i ++){
        output[i] = input[IP[i] - 1];
    }
}

void DES_System::Re_Ini_Permu(int input[], int output[]){
    int re_IP[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
    for(int i = 0; i < 64; i ++){
        output[i] = input[re_IP[i] - 1];
    }
}

void DES_System::E_extension(int input[], int output[]){
    int E[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
	for(int i = 0; i < Input_EXT; i ++){
        output[i] = input[E[i] - 1];
    }
}

void DES_System::LeftShift(int key[], int num){
    int res[56];
    for(int i = 0; i < KEY_SIZE/2; i ++){
        res[i] = key[(i + num) % 28];
    }
    for(int i = KEY_SIZE/2; i < KEY_SIZE; i ++){
        res[i] = key[(i - 28 + num) % 28 + 28];
    }
    for(int i = 0; i < KEY_SIZE; i ++){
        key[i] = res[i];
    }
}

void DES_System::SubKeyGen(int round_num, int input[], int output[]){
    int res[56];
    int PC1[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
    for(int i = 0; i < KEY_SIZE; i ++){	//PC1�û� 
        res[i] = input[PC1[i] - 1]; //cout << res[i] << endl;
    }
    int round_shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    for(int i = 0; i < round_num; i ++){  	//���� 
        LeftShift(res, round_shift[i]);
    }
    int PC2[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
    for(int i = 0; i < Input_EXT; i ++){	//PC2�û�
        output[i] = res[PC2[i] - 1];
    }
}

int SBox[8][4][16] = {  
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

void DES_System::Sbox_Permu(int input[], int output[]){
    for(int i = 0; i < 8; i ++){
        int row = input[i * 6] * 2+input[i * 6 + 5];
        int col = input[i * 6 + 1] * 8 + input[i * 6 + 2] * 4 + input[i * 6 + 3] * 2 + input[i * 6 + 4];
        //cout << row << col << endl;
        int temp = SBox[i][row][col];
        for(int j = 3; j >= 0; j--){ 
            output[i*4 + j] = temp % 2;
            temp /= 2;
        }
    }
}

void DES_System::P_Permu(int input[], int output[]){
    int P_Permu[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
    for(int i = 0; i < PLAIN_SIZE/2; i ++){ 
        output[i] = input[P_Permu[i] - 1];
    }
}


void DES_System::Round_Permu(int linput[], int rinput[], int loutput[], int routput[], int round_key[]){	
    for(int i = 0; i < PLAIN_SIZE/2; i ++){		//�󲿵ļ��� 
    	//cout << rinput[i] << endl;
        loutput[i] = rinput[i]; 
    }// Li = Ri-1
    int rinput_ext[48]; 
    E_extension(rinput, rinput_ext);   	//E��չ 
    int rintput_ext2[48];
    for(int i = 0; i < Input_EXT; i ++){    
    	//cout << rinput_ext[i] << endl;
        rintput_ext2[i] = rinput_ext[i] ^ round_key[i]; 
        //cout << rintput_ext2[i] << endl;
    }
    int rinput_s[32];
    Sbox_Permu(rintput_ext2, rinput_s);		//S���û� 
    int rinput_p[32];
    P_Permu(rinput_s, rinput_p);			//P�û� 
    int temp[32];
    for(int i = 0; i < PLAIN_SIZE/2; i ++){		//�Ҳ��ļ��� 
        temp[i] = rinput_p[i] ^ linput[i];
    }
    for(int i = 0; i < PLAIN_SIZE/2; i ++){
        routput[i] = temp[i];
    }
}

void DES_System::En(int input[], int output[], int key[]){
    int input_ip[64];
    Ini_Permu(input, input_ip);		//��ʼ�û� 
    int linput[32], rinput[32], loutput[32], routput[32], round_key[48];	//�������룬�������������Կ 
    for(int i = 0; i < PLAIN_SIZE / 2; i ++){	//��ʼ�û�����벿����Ϊ�����룬�Ұ벿����Ϊ������ 
        linput[i] = input_ip[i]; 
    }
    for(int i = PLAIN_SIZE / 2; i < PLAIN_SIZE; i ++){
        rinput[i - PLAIN_SIZE / 2] = input_ip[i];
    }
    for(int i = 1; i <= 16; i ++){			//ͨ����Կ��ȡ����Կ��������16�ֵ����û� 
        SubKeyGen(i, key, round_key);  
        Round_Permu(linput, rinput, loutput, routput, round_key); 
        for(int i = 0; i < PLAIN_SIZE/2; i ++) { 
            rinput[i] = routput[i];
        }
    }
    int res[64];
    for(int i = 0; i < PLAIN_SIZE / 2; i ++){	//���һ�ֵõ��Ľ������Ҫ���ҽ���λ�� 
        res[i] = routput[i];
    }
    for(int i = PLAIN_SIZE / 2; i < PLAIN_SIZE; i ++){
        res[i] = loutput[i - PLAIN_SIZE / 2];
    }
    Re_Ini_Permu(res, output);					//�Խ���������ʼ�û� 
}

void DES_System::De(int input[], int output[], int key[]){
    int input_ip[64];
    Ini_Permu(input, input_ip);		//��ʼ�û� 
    int linput[32], rinput[32], loutput[32], routput[32], round_key[48];
    for(int i = 0; i < PLAIN_SIZE / 2; i ++){	//���Ҳ𿪣��ֱ�32bit 
        linput[i] = input_ip[i];
    }
    for(int i = PLAIN_SIZE / 2; i < PLAIN_SIZE; i ++){
        rinput[i - PLAIN_SIZE / 2] = input_ip[i];	
    }
    for(int i = 16; i >= 1; i --){		//���û� 
        SubKeyGen(i, key, round_key);
        Round_Permu(linput, rinput, loutput, routput, round_key);
        for(int i = 0; i < PLAIN_SIZE/2; i ++) { 
            linput[i] = loutput[i];
            rinput[i] = routput[i];
        }
    }
    int res[64];
    for(int i = 0; i < PLAIN_SIZE / 2; i ++){	//���ҽ��� 
        res[i] = routput[i];
    }
    for(int i = PLAIN_SIZE / 2; i < PLAIN_SIZE; i ++){
        res[i] = loutput[i - PLAIN_SIZE / 2];
    }
    Re_Ini_Permu(res, output);			//���ʼ�û� 
}

class op_mode{
    public:
    op_mode(string mode);
    string mode_enc(string input, string key, string v, string outmode);
    string mode_dec(string input, string key, string v, string outmode);
    void choose_mode(string mode);

    private:
    string __mode = "ECB";
    string Bi2Hex(string input);
    string Hex2Bi(string input);
    string str2Bi(string input);
    string str_XOR(string a, string b);
    string ECB(string input, string key, string v, string outmode, string choose_en_de);
    string CBC(string input, string key, string v, string outmode, string choose_en_de);
    string CFB(string input, string key, string v, string outmode, string choose_en_de);
    string OFB(string input, string key, string v, string outmode, string choose_en_de);
    string CTR(string input, string key, string v, string outmode, string choose_en_de);
};

op_mode::op_mode(string mode){
    __mode = mode;
}

string op_mode::mode_enc(string input, string key, string v, string outmode){
    input = str2Bi(input);
    key = str2Bi(key);
    v = str2Bi(v);
	if(__mode == "ECB"){
		return ECB(input, key, v, outmode, "en");
	}
	else if(__mode == "CBC"){
		return CBC(input, key, v, outmode, "en");
	}
	else if(__mode == "CFB"){
		return CFB(input, key, v, outmode, "en");
	}
	else if(__mode == "OFB"){
		return OFB(input, key, v, outmode, "en");
	}
	else if(__mode == "CTR"){
		return CTR(input, key, v, outmode, "de");
	}
	else{
		return "error!";
	}
}

string op_mode::mode_dec(string input, string key, string v, string outmode){
    key = str2Bi(key);
    v = str2Bi(v);
	if(__mode == "ECB"){
		return ECB(input, key, v, outmode, "de");
	}
	else if(__mode == "CBC"){
		return CBC(input, key, v, outmode, "de");
	}
	else if(__mode == "CFB"){
		return CFB(input, key, v, outmode, "de");
	}
	else if(__mode == "OFB"){
		return OFB(input, key, v, outmode, "de");
	}
	else if(__mode == "CTR"){
		return CTR(input, key, v, outmode, "de");
	}
	else{
		return "error!";
	}
}

void op_mode::choose_mode(string mode){
    __mode = mode;
}

string op_mode::Hex2Bi(string input){
    map<char, string> trans;
    trans['0'] = "0000";
    trans['1'] = "0001";
    trans['2'] = "0010";
    trans['3'] = "0011";
    trans['4'] = "0100";
    trans['5'] = "0101";
    trans['6'] = "0110";
    trans['7'] = "0111";
    trans['8'] = "1000";
    trans['9'] = "1001";
    trans['a'] = "1010";
    trans['b'] = "1011";
    trans['c'] = "1100";
    trans['d'] = "1101";
    trans['e'] = "1110";
    trans['f'] = "1111";
    string output;
    for(int i = 0; i < input.size(); i ++){
        output+=trans[input[i]];
    }
    return output;
}

string op_mode::Bi2Hex(string input){
    map<string, string> rev;
    rev["0000"] = "0";
    rev["0001"] = "1";
    rev["0010"] = "2";
    rev["0011"] = "3";
    rev["0100"] = "4";
    rev["0101"] = "5";
    rev["0110"] = "6";
    rev["0111"] = "7";
    rev["1000"] = "8";
    rev["1001"] = "9";
    rev["1010"] = "a";
    rev["1011"] = "b";
    rev["1100"] = "c";
    rev["1101"] = "d";
    rev["1110"] = "e";
    rev["1111"] = "f";
    string output;
    for(int i = 0; i < input.size()/4; i ++){
        string s;
        for(int k = i*4; k < (i+1)*4; k ++){
            s.push_back(input[k]);
        }
        output+=rev[s];
    }
    return output;
}

string op_mode::str2Bi(string input){
    string output;
    char buff[10];
    for(int i = 0; i < input.size(); i ++){
        sprintf(buff, "%x", toascii(input[i]));
        output+=string(buff);
    }
    output = Hex2Bi(output);
    return output;
}

string op_mode::str_XOR(string a, string b){
    string res;
    for(int i = 0; i < a.size(); i ++){
        res.push_back((a[i]-'0')^(b[i]-'0')+'0');
    }
    return res;
}

string op_mode::ECB(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 64;
    while(input.size()%block_len != 0){		//����λ��䣬����������һ�鲻��64bit�����'0'���ܱ�64���� 
        input.push_back('0');
    }
    string res;
    int block_num = input.size() / block_len;	 //�������� 
    DES_System des;
    des.KeyGen(key, "bin");
    for(int i = 0; i < block_num; i ++){	//��ÿһ��ֱ���м��ܴ��� 
        if(choose_en_de == "en"){
            res +=des.Encryption(input.substr(i*block_len, block_len), "bin", "bin");
        }
        else{								//��ÿһ��ֱ���н��ܴ��� 
            res +=des.Decryption(input.substr(i*block_len, block_len), "bin", "bin");
        }
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::CBC(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 64;
    while(input.size()%block_len != 0){   
        input.push_back('0');
    }
    string res;
    int block_num = input.size() / block_len;
    if(choose_en_de == "en"){
        DES_System des;
        des.KeyGen(key, "bin");		
        res+=des.Encryption(str_XOR(input.substr(0, block_len), v), "bin", "bin");	//Ҫ�г�ʼ����v����һ������Ǻͳ�ʼ������� 
        for(int i = 1; i < block_num; i ++){	//ÿһ�ּ���Ϊ��ǰ���ĺ���һ�����ĵ�����ټ��� 
            res+=des.Encryption(str_XOR(input.substr(i*block_len, block_len), res.substr((i - 1)*block_len, block_len)), "bin", "bin");
        }     
    }
    else{
        DES_System des;
        des.KeyGen(key, "bin");
        res+=str_XOR(des.Decryption(input.substr(0, block_len), "bin", "bin"), v);	//������ͬ����DES�ļ����㷨��Ϊ�����㷨 
        for(int i = 1; i < block_num; i ++){
            res+=str_XOR(des.Decryption(input.substr(i*block_len, block_len), "bin", "bin"), input.substr((i-1)*block_len, block_len));
        }
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::CFB(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 8;
    while(input.size()% block_len !=0){
        input.push_back('0');
    }
    int block_num = input.size() / block_len;
    string res;
    if(choose_en_de == "en"){
        DES_System des;
        des.KeyGen(key, "bin");
        string v1 = v;
        string res1 = des.Encryption(v1, "bin", "bin");
        res+=str_XOR(res1.substr(0, block_len), input.substr(0, block_len));	//��һ����Ҫ�����ܽ�����ʼ����������� 
        for(int i = 1; i < block_num; i ++){		//�ڶ��鿪ʼ��ÿһ�鶼��ȡ����8bit������ܵ����Ľ������ 
            v1 = v1.substr(block_len, v1.size() - block_len) + res.substr((i - 1)*block_len, block_len);
            res1 = des.Encryption(v1, "bin", "bin");
            res+=str_XOR(res1.substr(0, block_len), input.substr(i*block_len, block_len));
        }
    }
    else{
        DES_System des;
        des.KeyGen(key, "bin");
        string v1 = v;
        string res1 = des.Encryption(v1, "bin", "bin");
        res+=str_XOR(res1.substr(0, block_len), input.substr(0, block_len));		//��һ����Ҫ���������ʼ�������ܽ���������
        for(int i = 1; i < block_num; i ++){
            v1 = v1.substr(block_len, v1.size() - block_len) + input.substr((i - 1)*block_len, block_len);
            res1 = des.Encryption(v1, "bin", "bin");
            res+=str_XOR(res1.substr(0, block_len), input.substr(i*block_len, block_len));		//���ܺ������8bit�����Ľ������ 
        }
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::OFB(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 64;
    while(input.size()% block_len !=0){
        input.push_back('0');
    }
    int block_num = input.size() / block_len;
    string res;
    DES_System des;
    if(choose_en_de == "en"){
        des.KeyGen(key, "bin");
        string v1 = v;
        for(int i = 0; i < block_num; i ++){
            v1 = des.Encryption(v1, "bin", "bin");
            res += str_XOR(v1, input.substr(i*block_len, block_len));	//�õ������������Ľ������ 
        }   
    }
    else{
        des.KeyGen(key, "bin");
        string v1 = v;
        for(int i = 0; i < block_num; i ++){
            v1 = des.Encryption(v1, "bin", "bin");
            res += str_XOR(v1, input.substr(i*block_len, block_len));	//�õ������������Ľ������ 
        }  
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::CTR(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 64;
    while(input.size()% block_len !=0){
        input.push_back('0');
    }
    int block_num = input.size() / block_len;
    string count = v;
    string res;
    DES_System des;
    des.KeyGen(key, "bin");
    for(int i = 0 ;i < block_num; i ++){
        string res1 = des.Encryption(count, "bin", "bin");
        res+= str_XOR(res1, input.substr(i*block_len, block_len));	//��ʱ�����������ģ����ģ�������� 
        if(count[count.size() - 1] == '0'){		//�õ���һ�ּ�ʱ����ֵ 
            count[count.size() - 1] = '1';
        }
        else{
            int pointer = count.size() - 1;
            while(count[pointer] == '1' && pointer >= 0){
                count[pointer] = '0';
                pointer --;
            }
            count[pointer] = '1';
        }
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}
