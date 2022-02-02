#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <utility>
#include <map>
using namespace std;

struct datatype{	//基本数据类型实现 
    bool *data = NULL;
    datatype();   
    datatype(string s);
    datatype(const datatype &other);
    datatype &operator = (const datatype &other);
    ~datatype();
    friend datatype operator ^ (const datatype &a, const datatype &b);  //使用友元函数实现异或运算 
};

datatype::datatype(){
    data=(bool *)malloc(8*sizeof(bool));
    memset(data,0,8*sizeof(bool));
}

datatype::datatype(string s){  	//初始化构造函数，利用输入的16进制的字符串进行构造 
    data=(bool *)malloc(8*sizeof(bool));
    map<char,string> trans;   
    trans['0']="0000"; trans['1']="0001"; trans['2']="0010"; trans['3']="0011"; trans['4']="0100"; trans['5']="0101"; trans['6']="0110"; trans['7']="0111"; trans['8']="1000"; trans['9']="1001"; trans['A']="1010"; trans['B']="1011"; trans['C']="1100"; trans['D']="1101"; trans['E']="1110"; trans['F']="1111";trans['a']="1010"; trans['b']="1011"; trans['c']="1100"; trans['d']="1101"; trans['e']="1110"; trans['f']="1111";
    for(int i=0;i<4;i++){
        data[i]=trans[s[2]][i]-'0';
    }
    for(int i=4;i<8;i++){
        data[i]=trans[s[3]][i-4]-'0';    
    }
}

datatype::datatype(const datatype &other){	//拷贝构造函数 
    data=(bool *)malloc(8*sizeof(bool));
    for(int i = 0;i < 8;i ++){
        data[i]=other.data[i];
    }
}

datatype &datatype::operator = (const datatype &other){	
    for(int i = 0; i < 8; i ++){
        data[i] = other.data[i];
    }
    return *this;
}

datatype::~datatype(){
    free(data);
}

void print(datatype a){
    for(int i = 0; i < 8; i ++){
        cout << a.data[i];
    }
}

datatype operator ^ (const datatype &a, const datatype &b){ 	//位异或运算，二元运算，应当在类外当友元函数 
    datatype res;
    for(int i = 0; i < 8; i ++){
        res.data[i] = a.data[i] ^ b.data[i];
    }
    return res;
}

class AES_System{
    public:
    string Encryption(string input, string scale_in, string scale_out);
    string Decryption(string input, string scale_in, string scale_out);
    void KeyGen(string key, string scale);

    private:
    datatype plain_mes[4][4], enc_mes[4][4], key_cur[4][4];
    string Bi2Hex(string input);
    string Hex2Bi(string input);
    void ColInput(string input, datatype a[4][4]);			//按列输入明文矩阵 
    void RowInput(string input);							//按行输入密钥矩阵 
    string stdOutput(datatype a[4][4]);						//将输出转化为字符串形式 
    void ByteSub(datatype input[4][4], datatype output[4][4]);
    void InvByteSub(datatype input[4][4], datatype output[4][4]);
    void ShiftRow(datatype input[4][4], datatype output[4][4]);
    void InvShiftRow(datatype input[4][4], datatype output[4][4]);
    datatype gfMulti_2(datatype input,int exp);				
    datatype multi_on_GF(datatype x, datatype y);				//有限域乘法 
    void MixColumn(datatype input[4][4], datatype output[4][4]);
    void InvMixColumn(datatype input[4][4], datatype output[4][4]);
    void KeyExpansion(datatype input[4][4], datatype output[44][4]);
    void KeyTransform(int col, datatype input[4], datatype output[4]);		//密钥生成过程中的T变换 
    void AddRoundKey(datatype input[4][4], datatype output[4][4], datatype roundkey[4][4]);
    void En(datatype input[4][4], datatype output[4][4], datatype key[4][4]);
    void De(datatype input[4][4], datatype output[4][4], datatype key[4][4]);
};

string AES_System::Encryption(string input, string scale_in, string scale_out){ 
    if(scale_in=="bin"){   
        input = Bi2Hex(input);
    }
    ColInput(input, plain_mes);		//将明文按列进行输入，方便运算 
    En(plain_mes, enc_mes, key_cur);	//加密过程 
    string output = stdOutput(enc_mes);	//将结果转化为标准输出 
    if(scale_out=="bin"){
        output = Hex2Bi(output);
    }
    return output;
}

string AES_System::Decryption(string input, string scale_in, string scale_out){
    if(scale_in=="bin"){    
        input = Bi2Hex(input);
    }
	ColInput(input, enc_mes);				//将密文按列进行输入，方便运算 
    De(enc_mes, plain_mes, key_cur);		//解密过程 
    string output = stdOutput(plain_mes);    //将结果转化为标准输出 
    if(scale_out=="bin"){
        output = Hex2Bi(output);
    }
    return output;
}

void AES_System::KeyGen(string key, string scale){
    if(scale == "bin"){
        key = Bi2Hex(key);
    }
    RowInput(key);
}

string AES_System::Hex2Bi(string input){
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

string AES_System::Bi2Hex(string input){
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

void AES_System::ColInput(string input, datatype a[4][4]){    
    int k = 0;
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j < 4; j ++){
            string t;
            t.push_back(input[k]);
            t.push_back(input[k+1]);
            t = "0x" + t;
            a[j][i] = datatype(t); 
            k = k + 2;
        }
    }
}

void AES_System::RowInput(string input){   
    int k = 0;
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j <4; j ++){
            string t;
            t.push_back(input[k]);
            t.push_back(input[k+1]);
            t = "0x" + t;
            key_cur[i][j] = datatype(t);
            k = k + 2;
        }
    }
}

string AES_System::stdOutput(datatype a[4][4]){
	string output;
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
    for(int i = 0;i < 4;i ++)
    {
        for(int j = 0;j < 4;j ++)
        {
            string m=to_string(a[j][i].data[0])+to_string(a[j][i].data[1])+to_string(a[j][i].data[2])+to_string(a[j][i].data[3]);
            string n=to_string(a[j][i].data[4])+to_string(a[j][i].data[5])+to_string(a[j][i].data[6])+to_string(a[j][i].data[7]);
            output+=(rev[m] + rev[n]);
        }
    }
    return output;
}

string S_Box[16][16] = {    
    "0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7", "0xab", "0x76",
    "0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4", "0x72", "0xc0",
    "0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8", "0x31", "0x15",
    "0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27", "0xb2", "0x75",
    "0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3", "0x2f", "0x84",
    "0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c", "0x58", "0xcf",
    "0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c", "0x9f", "0xa8",
    "0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff", "0xf3", "0xd2",
    "0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d", "0x19", "0x73",
    "0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e", "0x0b", "0xdb",
    "0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95", "0xe4", "0x79",
    "0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a", "0xae", "0x08",
    "0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd", "0x8b", "0x8a",
    "0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1", "0x1d", "0x9e",
    "0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55", "0x28", "0xdf",
    "0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54", "0xbb", "0x16" 
};

void AES_System::ByteSub(datatype input[4][4], datatype output[4][4]){
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j < 4; j ++){
            int row = input[i][j].data[0]*8 + input[i][j].data[1]*4 + input[i][j].data[2]*2 + input[i][j].data[3];	//前四位的值作为行 
            int col = input[i][j].data[4]*8 + input[i][j].data[5]*4 + input[i][j].data[6]*2 + input[i][j].data[7];	//后四位的值作为列 
            output[i][j] = datatype(S_Box[row][col]);	//通过S盒进行代换 
        }
    }
}

string Inv_S_Box[16][16] = {    
    "0x52", "0x09", "0x6a", "0xd5", "0x30", "0x36", "0xa5", "0x38", "0xbf", "0x40", "0xa3", "0x9e", "0x81", "0xf3", "0xd7", "0xfb",
    "0x7c", "0xe3", "0x39", "0x82", "0x9b", "0x2f", "0xff", "0x87", "0x34", "0x8e", "0x43", "0x44", "0xc4", "0xde", "0xe9", "0xcb",
    "0x54", "0x7b", "0x94", "0x32", "0xa6", "0xc2", "0x23", "0x3d", "0xee", "0x4c", "0x95", "0x0b", "0x42", "0xfa", "0xc3", "0x4e",
    "0x08", "0x2e", "0xa1", "0x66", "0x28", "0xd9", "0x24", "0xb2", "0x76", "0x5b", "0xa2", "0x49", "0x6d", "0x8b", "0xd1", "0x25",
    "0x72", "0xf8", "0xf6", "0x64", "0x86", "0x68", "0x98", "0x16", "0xd4", "0xa4", "0x5c", "0xcc", "0x5d", "0x65", "0xb6", "0x92",
    "0x6c", "0x70", "0x48", "0x50", "0xfd", "0xed", "0xb9", "0xda", "0x5e", "0x15", "0x46", "0x57", "0xa7", "0x8d", "0x9d", "0x84",
    "0x90", "0xd8", "0xab", "0x00", "0x8c", "0xbc", "0xd3", "0x0a", "0xf7", "0xe4", "0x58", "0x05", "0xb8", "0xb3", "0x45", "0x06",
    "0xd0", "0x2c", "0x1e", "0x8f", "0xca", "0x3f", "0x0f", "0x02", "0xc1", "0xaf", "0xbd", "0x03", "0x01", "0x13", "0x8a", "0x6b",
    "0x3a", "0x91", "0x11", "0x41", "0x4f", "0x67", "0xdc", "0xea", "0x97", "0xf2", "0xcf", "0xce", "0xf0", "0xb4", "0xe6", "0x73",
    "0x96", "0xac", "0x74", "0x22", "0xe7", "0xad", "0x35", "0x85", "0xe2", "0xf9", "0x37", "0xe8", "0x1c", "0x75", "0xdf", "0x6e",
    "0x47", "0xf1", "0x1a", "0x71", "0x1d", "0x29", "0xc5", "0x89", "0x6f", "0xb7", "0x62", "0x0e", "0xaa", "0x18", "0xbe", "0x1b",
    "0xfc", "0x56", "0x3e", "0x4b", "0xc6", "0xd2", "0x79", "0x20", "0x9a", "0xdb", "0xc0", "0xfe", "0x78", "0xcd", "0x5a", "0xf4",
    "0x1f", "0xdd", "0xa8", "0x33", "0x88", "0x07", "0xc7", "0x31", "0xb1", "0x12", "0x10", "0x59", "0x27", "0x80", "0xec", "0x5f",
    "0x60", "0x51", "0x7f", "0xa9", "0x19", "0xb5", "0x4a", "0x0d", "0x2d", "0xe5", "0x7a", "0x9f", "0x93", "0xc9", "0x9c", "0xef",
    "0xa0", "0xe0", "0x3b", "0x4d", "0xae", "0x2a", "0xf5", "0xb0", "0xc8", "0xeb", "0xbb", "0x3c", "0x83", "0x53", "0x99", "0x61",
    "0x17", "0x2b", "0x04", "0x7e", "0xba", "0x77", "0xd6", "0x26", "0xe1", "0x69", "0x14", "0x63", "0x55", "0x21", "0x0c", "0x7d" 
};

void AES_System::InvByteSub(datatype input[4][4], datatype output[4][4]){
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j < 4; j ++){
            int row = input[i][j].data[0]*8 + input[i][j].data[1]*4 + input[i][j].data[2]*2 + input[i][j].data[3];
            int col = input[i][j].data[4]*8 + input[i][j].data[5]*4 + input[i][j].data[6]*2 + input[i][j].data[7];
            output[i][j] = datatype(Inv_S_Box[row][col]);		////通过逆S盒进行置换
        }
    }
}

void AES_System::ShiftRow(datatype input[4][4], datatype output[4][4]){		//行移位：将其第i行的元素循环左移i位
    for(int i = 0;i < 4; i ++ ){   
        for(int j = 0; j < 4; j ++){
            output[i][j] = input[i][(i + j)%4];
        }
    }
}

void AES_System::InvShiftRow(datatype input[4][4], datatype output[4][4]){		//逆行移位：将其第i行的元素循环右移i位
    for(int i = 0;i < 4; i ++ ){   
        for(int j = 0; j < 4; j ++){
            output[i][j] = input[i][(j + 4 - i)%4];     //j + Nb - Ci
        }
    }
}


datatype AES_System::gfMulti_2(datatype input,int exp)
{	//计算输入值和2的幂的GF(2^8)有限域乘法结果
    if(exp==0)
    return input;
    else 
    {
        for(int k=0;k<exp;k++)
        {
        	bool first=input.data[0]; 	//在移位操作之前的输入数值的首位
        	for(int i=0;i<7;i++)
        	{//首先将输入左移一位，且右侧补0
            	input.data[i]=input.data[i+1];	
        	}
        	input.data[7]=0;
        	input=(first==0)?input:(input^datatype("0x1B"));
		}
		return input;
    }
}


datatype AES_System::multi_on_GF(datatype a,datatype b){//我们将输入b进行分解，然后遍历输入b的每一个二进制位，若二进制位b.data[i]为1，则将结果异或gfMulti_2(a,8-i-1)
    datatype res;
    for(int i=0;i<8;i++)
    {
        if(b.data[i]==1)
        {
            res=res^gfMulti_2(a,8-i-1);   
        }
    }
    return res;
}

void AES_System::MixColumn(datatype input[4][4], datatype output[4][4]){
    for(int i = 0; i < 4; i ++){
        /*列混合表 
          2,3,1,1
          1,2,3,1
          1,1,2,3
          3,1,1,2*/
        output[0][i] = multi_on_GF(input[0][i], datatype("0x02"))^multi_on_GF(input[1][i], datatype("0x03"))^input[2][i]^input[3][i];
        output[1][i] = input[0][i]^multi_on_GF(input[1][i], datatype("0x02"))^multi_on_GF(input[2][i], datatype("0x03"))^input[3][i];
        output[2][i] = input[0][i]^input[1][i]^multi_on_GF(input[2][i], datatype("0x02"))^multi_on_GF(input[3][i], datatype("0x03"));
        output[3][i] = multi_on_GF(input[0][i], datatype("0x03"))^input[1][i]^input[2][i]^multi_on_GF(input[3][i], datatype("0x02"));
    }
}

void AES_System::InvMixColumn(datatype input[4][4], datatype output[4][4]){
    for(int i = 0; i < 4; i ++){
        /*逆列混合表 
          e,b,d,9
          9,e,b,d
          d,9,e,b
          b,d,9,e*/
        output[0][i]=multi_on_GF(input[0][i],datatype("0x0E"))^multi_on_GF(input[1][i],datatype("0x0B"))^multi_on_GF(input[2][i],datatype("0x0D"))^multi_on_GF(input[3][i],datatype("0x09"));
        output[1][i]=multi_on_GF(input[0][i],datatype("0x09"))^multi_on_GF(input[1][i],datatype("0x0E"))^multi_on_GF(input[2][i],datatype("0x0B"))^multi_on_GF(input[3][i],datatype("0x0D"));
        output[2][i]=multi_on_GF(input[0][i],datatype("0x0D"))^multi_on_GF(input[1][i],datatype("0x09"))^multi_on_GF(input[2][i],datatype("0x0E"))^multi_on_GF(input[3][i],datatype("0x0B"));
        output[3][i]=multi_on_GF(input[0][i],datatype("0x0B"))^multi_on_GF(input[1][i],datatype("0x0D"))^multi_on_GF(input[2][i],datatype("0x09"))^multi_on_GF(input[3][i],datatype("0x0E"));
    }
}


string Rcon[10][4] = {
    "0x01","0x00","0x00","0x00",
    "0x02","0x00","0x00","0x00",
    "0x04","0x00","0x00","0x00",
    "0x08","0x00","0x00","0x00",
    "0x10","0x00","0x00","0x00",
    "0x20","0x00","0x00","0x00",
    "0x40","0x00","0x00","0x00",
    "0x80","0x00","0x00","0x00",
    "0x1B","0x00","0x00","0x00",
    "0x36","0x00","0x00","0x00"
};

void AES_System::KeyTransform(int col, datatype input[4], datatype output[4]){
    //循环左移一个字节
    for(int i = 0; i < 4; i ++){
        output[i] = input[(i + 1) % 4];
    }
    //S盒字节代换
    for(int i = 0; i < 4; i ++){
        int row = output[i].data[0]*8 + output[i].data[1]*4 + output[i].data[2]*2 + output[i].data[3];
        int col = output[i].data[4]*8 + output[i].data[5]*4 + output[i].data[6]*2 + output[i].data[7];
        output[i] = datatype(S_Box[row][col]);
    }
    //Rc[i] = 01, 02, 04, 08, 10, 20, 40, 80, 1B, 36
	//轮常量异或操作
    for(int i = 0; i < 4; i ++){
        output[i] = output[i]^Rcon[col/4 - 1][i];
    }
}

void AES_System::KeyExpansion(datatype input[4][4], datatype output[44][4]){
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j < 4; j ++){    //输出的前4行和输入的前4列相同
            output[i][j] = input[i][j];
        }
    }
    for(int i = 4; i < 44; i ++){
        if(i % 4 != 0){
            for(int j = 0; j < 4; j ++){	//第i行密钥由第i-1行和第i-4行异或得到
                output[i][j] = output[i-1][j] ^ output[i-4][j];     
            }
        }
        else{
            datatype res[4];
            KeyTransform(i, output[i-1], res);
            for(int j = 0; j < 4; j ++){	//则第i行密钥通过第i-4行的密钥，以及第i-1行的密钥经过变换后的结果异或而得到
                output[i][j] = res[j]^output[i-4][j];
            }
        }
    }
}


void AES_System::AddRoundKey(datatype input[4][4], datatype output[4][4], datatype roundkey[4][4]){
    for(int i = 0; i < 4; i ++){
        for(int j = 0; j < 4; j ++){    //与子密钥的转置进行轮密钥加操作  
            output[i][j] = input[i][j]^roundkey[j][i];
        }
    }
}



void AES_System::En(datatype input[4][4], datatype output[4][4], datatype key[4][4]){
    datatype roundkey[44][4];
    KeyExpansion(key, roundkey);//密钥扩展 
    datatype added_res[4][4];
    AddRoundKey(input, added_res, roundkey);//轮密钥生成 
    for(int i = 0 ; i < 9; i ++){   //前9轮加密 
        datatype sub_res[4][4];
        datatype shift_row_res[4][4];
        datatype mix_col_res[4][4];
        ByteSub(added_res, sub_res);
        ShiftRow(sub_res, shift_row_res);
        MixColumn(shift_row_res, mix_col_res);
        AddRoundKey(mix_col_res, added_res, roundkey+4*(i + 1));
    }
    //第十轮不包含列混合的过程 
    datatype sub_res[4][4];
    datatype shift_row_res[4][4];
    ByteSub(added_res, sub_res);
    ShiftRow(sub_res, shift_row_res);
    AddRoundKey(shift_row_res, output, roundkey+4*10);
}

void AES_System::De(datatype input[4][4], datatype output[4][4], datatype key[4][4]){
    datatype roundkey[44][4];
    KeyExpansion(key, roundkey);//密钥扩展 
    datatype inv_mix_col_res[4][4];
    AddRoundKey(input, inv_mix_col_res, roundkey+4*10);
    for(int i = 8 ; i >= 0; i --){   //从后面开始往前面 
        datatype inv_sub_res[4][4];
        datatype inv_shift_row_res[4][4];
        datatype added_res[4][4];
        InvShiftRow(inv_mix_col_res, inv_shift_row_res);
        InvByteSub(inv_shift_row_res, inv_sub_res);
        AddRoundKey(inv_sub_res, added_res, roundkey+4*(i + 1));
        InvMixColumn(added_res, inv_mix_col_res);
    }
    //第一轮单独处理，没有逆列混合 
    datatype inv_sub_res[4][4];
    datatype inv_shift_row_res[4][4];
    datatype added_res[4][4];
    InvShiftRow(inv_mix_col_res, inv_shift_row_res);
    InvByteSub(inv_shift_row_res, inv_sub_res);
    AddRoundKey(inv_sub_res, added_res, roundkey);
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
		return CTR(input, key, v, outmode, "en");
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
    int block_len = 128;
    while(input.size()%block_len != 0){    
        input.push_back('0');
    }
    string res;
    int block_num = input.size() / block_len;
    cout << block_num << endl;
    AES_System aes;
    aes.KeyGen(key, "bin");
    for(int i = 0; i < block_num; i ++){
        if(choose_en_de == "en"){
            res +=aes.Encryption(input.substr(i*block_len, block_len), "bin", "bin");
        }
        else{
            res +=aes.Decryption(input.substr(i*block_len, block_len), "bin", "bin");
        }
	}
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::CBC(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 128;
    while(input.size()%block_len != 0){   
        input.push_back('0');
    }
    string res;
    int block_num = input.size() / block_len;
    cout << block_num << endl;
    if(choose_en_de == "en"){
        AES_System aes;
        aes.KeyGen(key, "bin");
        res+=aes.Encryption(str_XOR(input.substr(0, block_len), v), "bin", "bin");
        for(int i = 1; i < block_num; i ++){
            res+=aes.Encryption(str_XOR(input.substr(i*block_len, block_len), res.substr((i - 1)*block_len, block_len)), "bin", "bin");
        }     
    }
    else{
        AES_System aes;
        aes.KeyGen(key, "bin");
        res+=str_XOR(aes.Decryption(input.substr(0, block_len), "bin", "bin"), v);
        for(int i = 1; i < block_num; i ++){
            res+=str_XOR(aes.Decryption(input.substr(i*block_len, block_len), "bin", "bin"), input.substr((i-1)*block_len, block_len));
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
        AES_System aes;
        aes.KeyGen(key, "bin");
        string v1 = v;
        string res1 = aes.Encryption(v1, "bin", "bin");
        res+=str_XOR(res1.substr(0, block_len), input.substr(0, block_len));
        for(int i = 1; i < block_num; i ++){
            v1 = v1.substr(block_len, v1.size() - block_len) + res.substr((i - 1)*block_len, block_len);
            res1 = aes.Encryption(v1, "bin", "bin");
            res+=str_XOR(res1.substr(0, block_len), input.substr(i*block_len, block_len));
        }
    }
    else{
        AES_System aes;
        aes.KeyGen(key, "bin");
        string v1 = v;
        string res1 = aes.Encryption(v1, "bin", "bin");
        res+=str_XOR(res1.substr(0, block_len), input.substr(0, block_len));
        for(int i = 1; i < block_num; i ++){
            v1 = v1.substr(block_len, v1.size() - block_len) + input.substr((i - 1)*block_len, block_len);
            res1 = aes.Encryption(v1, "bin", "bin");
            res+=str_XOR(res1.substr(0, block_len), input.substr(i*block_len, block_len));
        }
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::OFB(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 128;
    while(input.size()% block_len !=0){
        input.push_back('0');
    }
    int block_num = input.size() / block_len;
    string res;
    AES_System aes;
    if(choose_en_de == "en"){
        aes.KeyGen(key, "bin");
        string v1 = v;
        for(int i = 0; i < block_num; i ++){
            v1 = aes.Encryption(v1, "bin", "bin");
            res += str_XOR(v1, input.substr(i*block_len, block_len));
        }   
    }
    else{
        aes.KeyGen(key, "bin");
        string v1 = v;
        for(int i = 0; i < block_num; i ++){
            v1 = aes.Encryption(v1, "bin", "bin");
            res += str_XOR(v1, input.substr(i*block_len, block_len));
        }  
    }
    if(outmode == "hex"){
        res = Bi2Hex(res);
    }
    return res;
}

string op_mode::CTR(string input, string key, string v, string outmode, string choose_en_de){
    int block_len = 128;
    while(input.size()% block_len !=0){
        input.push_back('0');
    }
    int block_num = input.size() / block_len;
    string count = v;
    string res;
    AES_System aes;
    aes.KeyGen(key, "bin");
    for(int i = 0 ;i < block_num; i ++){
        string res1 = aes.Encryption(count, "bin", "bin");
        res+= str_XOR(res1, input.substr(i*block_len, block_len));
        if(count[count.size() - 1] == '0'){
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












