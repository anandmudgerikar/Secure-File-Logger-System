//============================================================================
// Name        : logger.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include "base64.h"
#include "Crypto.h"
#include <string>
#include <sstream>
#define PRINT_KEYS
using namespace std;

Crypto generate_KeyRSA()
{
	Crypto crypto;
	#ifdef PRINT_KEYS
	FILE* pFile = NULL;
	// Write the RSA keys to stdout
	pFile = fopen("privkey_Server.pem","wt");
	crypto.writeKeyToFile(pFile, KEY_SERVER_PRI);
	fclose(pFile);
	pFile = fopen("pubkey_Server.pem","wt");
	crypto.writeKeyToFile(pFile, KEY_SERVER_PUB);
	fclose(pFile);
	pFile = fopen("privkey_Client.pem","wt");
	crypto.writeKeyToFile(pFile, KEY_CLIENT_PRI);
	fclose(pFile);
	pFile = fopen("pubkey_Client.pem","wt");
	crypto.writeKeyToFile(pFile, KEY_CLIENT_PUB);
	fclose(pFile);
	#endif
	return crypto;
}


struct logs{
		int logfile_id;
		string logfile_name;
		ofstream logFile;
		bool isopen;
		int dl[100];
		int no_of_logs;
};

int main() {

Crypto crypto = generate_KeyRSA();
struct logs log[MAX_LOGFILES];

for(int x=0;x<MAX_LOGFILES;x++)
{
		log[x].logfile_id = 0;
		log[x].logfile_name = "empty";
		log[x].isopen = false;
		log[x].no_of_logs=0;
		for (int i=0;i<10;i++)
			log[x].dl[i]=0;
}

int in;
string command= "";
string comm1,comm2,comm3,command1;
unsigned char *encMsg = NULL;
unsigned char *encMsg3 = NULL;
unsigned char *encMsg2 = NULL;
unsigned char *decMsg = NULL;
unsigned char *decMsg2 = NULL;
unsigned char *ek;
unsigned char *iv;
unsigned char digest[EVP_MAX_MD_SIZE];
size_t ekl;
size_t ivl;
unsigned int decMsgLen;
unsigned int decMsg2Len;
unsigned int encMsgLen;
unsigned int encMsg2Len;
unsigned int encMsg3Len;
unsigned int md_len;
unsigned int sig_len=64;
unsigned char *sig_buf = new unsigned char[sig_len];
unsigned int log_file_count =1;
ofstream logFile;
unsigned char *a_0 = new unsigned char[32];
unsigned char *a_perm = new unsigned char[32];
unsigned char *y_0 = new unsigned char[32];
bool flag=true,verified=false,verified1=false;


while(1)
{
	in=0;
	printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	printf("Log into\n"
			"1. Trusted Server \n"
			"2. Untrusted Machine \n"
			"3. Verifier");
	printf("\n\nEnter you choice\n\n");
	cin>>in;
	if(in==1)
	{

		printf("Welcome to Trusted Server. Enter command \n");
		cin.ignore();
		getline(cin , command);
		//cout<<command;
		string delimiter = " ";
		size_t pos=0;
		int i=0;
		while (i != 3) {
			pos = command.find(delimiter);
			if(i==0){
			comm1 = command.substr(0, pos);
			//cout<<"command: "<<comm1<<endl;
			}
			if(i==1){
			comm2 = command.substr(0, pos);
			//cout<<"filename: "<<comm2<<endl;
			}
			if(i==2){
			comm3 = command.substr(0, pos);
			//cout<<"output filename: "<<comm3<<endl;
			}
			command.erase(0, (pos + delimiter.length()));
			i++;
		}
		//cout<<comm1<<" "<<comm2<<" "<<comm3;
		if(comm1 == "verifylog")
		{
			//cout<<endl<<"yo"<<endl;
			unsigned int x=1;
			bool flag4=false;

			while( x<=(log_file_count-1))
			{
				//cout<<endl<<"No of logs in file"<<x<<" : "<<log[x].no_of_logs<<endl;
				//cout<<endl<<"filename: "<<log[x].logfile_name<<endl;
				if(log[x].logfile_name.compare(comm2)==0)
				{
					//cout<<endl<<"file found.."<<endl;
					if(log[x].logFile.is_open())
					{
					cout<<endl<<"Failed Verification..Cannot verify file while it is open"<<endl;
					break;
					}
					else
					{
					//	cout<<endl<<"Starting Verification..."<<endl;
					//	cout<<endl<<"Reading file..."<<endl;
						flag4=true;

						ifstream myfile (log[x].logfile_name.c_str(), ios::binary | ios::in);
						unsigned char *req_log_entry = new unsigned char[2000];
						int j=0;
						bool flag3=false;

						ofstream outputfile;
						outputfile.open((comm3).c_str(), ios_base::out | ios_base::app);

						while(j<log[x].no_of_logs)
						{
							//cout<<endl<<"size of encrypted message:"<<log[x].dl[j]<<endl;

							if(!(myfile.read((char*)req_log_entry,log[x].dl[j]+LOG_ENTRY_TYPE_LENGTH+64+strlen("\nLOGENTRYSEPERATOR\n"))))
							{
								//running verification loop

								//verification loop ending

								cout<<endl<<"Something went wrong while reading.."<<endl;
								flag3=true;
								break;
							}


					if(j>=2 && j != (log[x].no_of_logs-1))
					{
						//cout<<endl<<j<<" : "<<req_log_entry<<endl;
						const char *log_file_id = new char[LOG_FILE_ID_LENGTH +1];
						std::stringstream ss;
						ss << (x);
						std::string str;
						ss >> str;
						log_file_id = str.c_str();
						//cout <<endl<<"Log id:"<<log_file_id<<endl;
						//cout<<endl<<"Required log entry no:"<<j<<endl;
						//cout<<endl<<log[x].dl[j]<<endl;

						unsigned char *data = new unsigned char[log[x].dl[j]];
						memcpy(data,req_log_entry+LOG_ENTRY_TYPE_LENGTH,log[x].dl[j]);
						unsigned char *y_f = new unsigned char[32];
						memcpy(y_f,req_log_entry+LOG_ENTRY_TYPE_LENGTH+log[x].dl[j],Y_0_LENGTH);
						unsigned char *z_f = new unsigned char[32];
						memcpy(z_f,req_log_entry+LOG_ENTRY_TYPE_LENGTH+log[x].dl[j]+Y_0_LENGTH,Z_0_LENGTH);

						//cout<<endl<<"Trusted party calculating a_f from a_0.."<<endl;
						int h=0;
						unsigned char *a_f = new unsigned char[32];
						memcpy(a_f,a_perm,32);
						while(h<=(j-1))
						{
							if(!(i = crypto.hash(a_f,32,digest,md_len))){
								fprintf(stderr, "Hashing failed\n");
							}
							memcpy(a_f,digest,32);
							h++;
						}

						//cout<<endl<<"Checking if values of z_f and y_f are correct.."<<endl;

						if(!(i = crypto.hmac(y_f,Y_0_LENGTH,a_f,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}
						unsigned char *z_check = new unsigned char[32];
						memcpy(z_check,digest,32);
						//cout<<endl<<z_f<<endl;
						//cout<<endl<<digest<<endl;
						//cout<<endl<<z_check<<endl;

						if( strncmp((const char*)z_f,(const char*)z_check,32) == 0)
						{
							//cout<<endl<<"Successfully verified.."<<endl;
							//cout<<endl<<"Sending key of the log entry to Verifier"<<endl;
							//cout<<endl<<"Generating Encryption Key.."<<endl;
							unsigned char *log_entry_type = (unsigned char*)"00005";
							if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_f,32,digest,md_len))){
								fprintf(stderr, "Hashing failed\n");
							}

							unsigned char *key = new unsigned char[32+1];
							memcpy(key,digest,32);
							//cout<<endl<<"Encryption Key Created..."<<endl;
							//cout<<endl<<"Sending decryption key to Verifier"<<endl;

							crypto.setAESKey(key,32);
							if((decMsg2Len = crypto.aesDecrypt(data,log[x].dl[j], (unsigned char**)&decMsg2)) == -1) {
								fprintf(stderr, "Decryption failed\n");
								return 1;
							}
							//cout<<endl<<"The decrypted message is:"<<decMsg2<<endl;
							outputfile<<decMsg2<<"\n";

						}

						}
					j++;
						}

						if(flag3)
							break;
					}
					}
				if(flag4)
					break;
					x++;
			}
			if(x==log_file_count)
			{
				cout<<endl<<"No such file found..."<<endl;
			}
		}
		else if(comm1 == "exit")
		{
			cout<<endl<<"PEACE!!!"<<endl;
			exit(1);
		}
		else
		{
			cout<<endl<<"You have entered incorrect command..try again"<<endl;
			continue;
		}
	}
	else if(in==2)
		{
			char *machine_id = new char[MACHINE_ID_LENGTH +1];
			machine_id = (const char*)"00001";
			//cout <<endl<<"Untrused machine id:"<<machine_id<<endl;
			printf("Welcome to Untrusted Machine. Enter command \n");

			int append_l;

			cin.ignore();
			getline(cin , command);
			//cout<<command;
			command1=command;
			string delimiter = " ";
			size_t pos=0;
			int i=0;
			while (i != 2) {
				pos = command.find(delimiter);
			    if(i==0){
				comm1 = command.substr(0, pos);
				append_l=pos;
				//cout<<"command: "<<comm1<<endl;
			    }
			    if(i==1){
			    comm2 = command.substr(0, pos);
			    //cout<<"filename: "<<comm2<<endl;
			    }
			    command.erase(0, (pos + delimiter.length()));
			    i++;

			}
			//cout<<comm1<<" "<<comm2;

	if(comm1 == "newlog")
	{
				int j=0;
				while(j < MAX_LOGFILES)
					{
						if(log[j].logfile_name.compare(comm2) == 0)
							{
							flag = false;
							}

							j++;
					}

				if(flag)
							{


							//cout<<endl<<"Creating Log File"<<endl;
							log[log_file_count].logFile.open((comm2).c_str(),std::ios_base::binary|std::ios_base::out | std::ios_base::app);
							log[log_file_count].logfile_id = log_file_count;
							log[log_file_count].logfile_name.assign(comm2);
							log[log_file_count].isopen = true;
							log_file_count++;
							//cout<<endl<<"Log File created"<<endl;

							/*
			  	  	  	  	cout<<endl<<"Creating new log"<<endl;
							cout<<endl<<"Starting Initialization process.."<<endl;
							cout<<endl<<"Creating Symmetric Key for Encryption.."<<endl;
							cout<<endl<<"Symmetric AES 128 bit Key  created"<<endl;
							*/

							const char *log_file_id = new char[LOG_FILE_ID_LENGTH +1];
							std::stringstream ss;
							ss << log_file_count;
							std::string str;
							ss >> str;
							log_file_id = str.c_str();
							//cout <<endl<<"Log id:"<<log_file_id<<endl;

							char *protocol_step_id = new char[PROTOCOL_ID_LENGTH +1];
							protocol_step_id = (const char*)"00001";
							//cout <<endl<<"protocol step id:" << protocol_step_id<<endl;

							std::time_t timestamp = std::time(0);
							char *ts = new char[TIMESTAMP_LENGTH +1];
							ts = asctime( localtime(&timestamp) );
							//cout <<endl<< "timestamp:"<<ts<<endl ;

							std::time_t timeout = std::time(0)+100;
							char *to = new char[TIMESTAMP_LENGTH +1];
							to = asctime( localtime(&timeout) );
							//cout <<endl<< "timeout at:"<<to<<endl ;


							int cert_length;
							char *cert;
							std::ifstream t;


							t.open("certServer.pem",ios::in);      // open input file
							t.seekg(0, std::ios::end);    // go to the end
							cert_length = t.tellg();           // report location (this is the length)
							t.seekg(0, std::ios::beg);    // go back to the beginning
							cert = new char[cert_length];    // allocate memory for a buffer of appropriate dimension
							t.read(cert, cert_length);       // read the whole file into the buffer
							t.close();
							//cout<<"certificate: "<<cert<<endl;


							RAND_bytes(a_0,32);
							memcpy(a_perm,a_0,32);
							//cout<<endl<<"authentication key: "<<a_0;

							//cout<<endl<<"Creating X0.."<<endl;
							unsigned int x_length= PROTOCOL_ID_LENGTH + TIMESTAMP_LENGTH +cert_length +32  ;
							unsigned char *x_0= new unsigned char[x_length];
							memcpy (x_0,protocol_step_id,PROTOCOL_ID_LENGTH);
							memcpy (x_0+PROTOCOL_ID_LENGTH,ts,TIMESTAMP_LENGTH);
							memcpy (x_0+PROTOCOL_ID_LENGTH+TIMESTAMP_LENGTH,cert,cert_length);
							memcpy (x_0+PROTOCOL_ID_LENGTH+TIMESTAMP_LENGTH+cert_length,a_0,32);

							//cout<<endl<<"X_0: "<<x_0<<endl;
							unsigned char *k_0 = new unsigned char[32];
							RAND_bytes(k_0,32);

							//cout<<endl<<"Creating signed x_0"<<endl;

							EVP_MD_CTX *mdctx = NULL;
							if(!(mdctx = EVP_MD_CTX_create()))
								printf("\nerror in signature \n");
							if(i = crypto.sign_alt(x_0,x_length,sig_buf,sig_len,mdctx,"privkeyServer.pem","cert_Server.pem")){
							fprintf(stderr, "Signing failed\n");
							}

							unsigned char *signed_x0 = new unsigned char[sig_len];
							signed_x0 =	&sig_buf[0];
							//cout<<endl<<"pointer:"<<signed_x0<<endl;
							//cout<<endl<<"buffer length:"<<sig_len<<endl;

							unsigned int msg2_length;
							msg2_length = (x_length + sig_len);
							unsigned char *msg2 = new unsigned char[msg2_length];
							memcpy (msg2,x_0,x_length);
							memcpy (msg2 + x_length,signed_x0,sig_len);
							//cout<<endl<<"Encrypting X0 with session key.."<<endl;
							crypto.setAESKey(k_0,32);
							if((encMsg2Len = crypto.aesEncrypt((const unsigned char*)msg2, msg2_length, &encMsg2)) == -1) {
							fprintf(stderr, "Encryption failed\n");
							return 1;
							}
							//cout<<endl<<"AES encryption with session key successful.."<<endl;
							//cout<<endl<<"Encrypting session key with public key of trusted machine.."<<endl;

							if((encMsgLen = crypto.rsaEncrypt(k_0,32, &encMsg, &ek, &ekl, &iv, &ivl)) == -1) {
							fprintf(stderr, "Encryption failed\n");
							}

							//cout<<endl<<"Building m0..."<<endl;
							unsigned  int m_length= PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH + encMsgLen + encMsg2Len;
							unsigned char *m_0= new unsigned char[m_length];
							memcpy (m_0,protocol_step_id,PROTOCOL_ID_LENGTH);
							memcpy (m_0+PROTOCOL_ID_LENGTH,machine_id,MACHINE_ID_LENGTH);
							memcpy (m_0+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH,encMsg,encMsgLen);
							memcpy (m_0+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH+encMsgLen,encMsg2,encMsg2Len);
							//cout<<endl<<"m0 built..."<<endl;
							//cout<<endl<<m_0<<endl;

							//cout<<endl<<"Creating First Log Entry"<<endl;
							unsigned char *log_entry_type = new unsigned char[LOG_ENTRY_TYPE_LENGTH +1];
							log_entry_type = (unsigned char*)"00001"; //log initialiaztion type

							unsigned int data_length = TIMESTAMP_LENGTH + TIMESTAMP_LENGTH + LOG_FILE_ID_LENGTH + m_length;
							unsigned char *data = new unsigned char[data_length];
							memcpy (data,ts,TIMESTAMP_LENGTH);
							memcpy (data+TIMESTAMP_LENGTH,to,TIMESTAMP_LENGTH);
							memcpy (data+TIMESTAMP_LENGTH+TIMESTAMP_LENGTH,log_file_id,LOG_FILE_ID_LENGTH);
							memcpy (data+TIMESTAMP_LENGTH+TIMESTAMP_LENGTH+LOG_FILE_ID_LENGTH,m_0,m_length);

							//cout<<endl<<"Generating Encryption Key.."<<endl;
							if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_0,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
							}
							unsigned char *key = new unsigned char[32+1];
							memcpy(key,digest,32);
							//cout<<endl<<"Encryption Key Created..."<<endl;

							//cout<<endl<<"Encrypting data with the key..."<<endl;
							crypto.setAESKey(digest,32);
							if((encMsg3Len = crypto.aesEncrypt((const unsigned char*)data, data_length, &encMsg3)) == -1) {
								fprintf(stderr, "Encryption failed\n");
								return 1;
							}

							log[log_file_count-1].dl[log[log_file_count-1].no_of_logs]=encMsg3Len;
							log[log_file_count-1].no_of_logs++;

							//cout<<endl<<"Creating hash chain..."<<endl;
							memcpy(y_0,"00000000000000000000000000000000",32);


							unsigned int y_0_length = 32;
							if(!(i = crypto.hash(y_0,y_0_length,(unsigned char*)data,data_length,(unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,digest,md_len))){
								fprintf(stderr, "Hashing failed\n");
							}
							memcpy(y_0,digest,32);

							cout<<endl<<"Creating HMAC..."<<endl;
							if(!(i = crypto.hmac(y_0,y_0_length,a_0,32,digest,md_len))){
								fprintf(stderr, "Hashing failed\n");
							}
							unsigned char *z_0 = new unsigned char[32];
							printf("\n");

							//cout<<endl<<"Creating A_1...."<<endl;
							if(!(i = crypto.hash(a_0,32,digest,md_len))){
								fprintf(stderr, "Hashing failed\n");
							}
							memcpy(a_0,(unsigned char*)digest,32);
							//cout<<endl<<"Created A_1...."<<endl;

							cout<<endl<<"Creating Log Entry.."<<endl;
							unsigned int log_entry_length = LOG_ENTRY_TYPE_LENGTH + encMsg3Len + y_0_length + Z_0_LENGTH ;
							unsigned char *log_entry = new unsigned char[log_entry_length];
							memcpy (log_entry,log_entry_type,LOG_ENTRY_TYPE_LENGTH);
							memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH,encMsg3,encMsg3Len);
							memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len,y_0,y_0_length);
							memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len+y_0_length,z_0,Z_0_LENGTH);
							//cout<<log_entry_length<<endl;
							//cout<<encMsg3Len<<endl;
							//cout<<y_0_length<<endl;
							//cout<<endl<<log_entry<<endl;
							//cout<<endl<<"Log Entry created"<<endl;

							//cout<<endl<<"Storing log entry.."<<endl;
							//cout<<endl<<log_file_count<<endl;
							log[log_file_count-1].logFile.write((const char*)log_entry,log_entry_length);
							log[log_file_count-1].logFile.write("\nLOGENTRYSEPERATOR\n",strlen("\nLOGENTRYSEPERATOR\n"));

							unsigned int mv_length= PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH + encMsgLen + encMsg2Len;
							unsigned char *mv_0= new unsigned char[mv_length];
							memcpy (encMsg,m_0+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH,encMsgLen);


							if((decMsgLen = crypto.rsaDecrypt(encMsg,encMsgLen, ek, ekl, iv, ivl, (unsigned char**)&decMsg)) == -1) {
								fprintf(stderr, "Decryption failed\n");
							}
							unsigned char *kv = new unsigned char[32];
							memcpy(kv,decMsg,32);
							//cout<<endl<<kv<<endl;

							//decrypting AES encryption now using kv
							crypto.setAESKey(kv,32);
							if((decMsg2Len = crypto.aesDecrypt(m_0+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH+encMsgLen,encMsg2Len, (unsigned char**)&decMsg2)) == -1) {
							fprintf(stderr, "Decryption failed\n");
							return 1;
							}

							unsigned char *xv = new unsigned char[x_length];
							memcpy(xv,decMsg2,x_length);

							unsigned char *certificate = new unsigned char[sig_len];
							memcpy(certificate,decMsg2 + x_length, sig_len);
							//cout<<endl<<certificate<<endl;

							if(i = crypto.verify_alt(mdctx,xv,x_length, sig_buf,sig_len,"privkeyServer.pem","cert_Server.pem")){
								fprintf(stderr, "Signing failed\n");
							}
							else
							{
								verified =true;
							}

							if(verified)
							{

								//cout<<endl<<"Trusted machine accepts..."<<endl;
								//cout<<endl<<"Trusted machine start building m1"<<endl;

								unsigned int x1_length = MACHINE_ID_LENGTH + LOG_FILE_ID_LENGTH + 32 ;
								unsigned char *x1 = new unsigned char[x1_length];
								machine_id = "00000";
								if(!(i = crypto.hash(xv,x_length,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
									break;
								}
								//cout<<endl<<digest<<endl;
								memcpy(x1,machine_id,MACHINE_ID_LENGTH);
								memcpy(x1+MACHINE_ID_LENGTH,log_file_id,LOG_FILE_ID_LENGTH);
								memcpy(x1+MACHINE_ID_LENGTH+LOG_FILE_ID_LENGTH,digest,32);

								//cout<<endl<<"preparing m1..."<<endl;

								unsigned char *k_1 = new unsigned char[32];
								RAND_bytes(k_1,32);


								//cout<<endl<<"Creating signed x_1"<<endl;

								EVP_MD_CTX *mdctx = NULL;
								if(!(mdctx = EVP_MD_CTX_create()))
								printf("\nerror in signature \n");
								if(i = crypto.sign_alt(x1,x1_length,sig_buf,sig_len,mdctx,"privkeyClient.pem","cert_Client.pem")){
									fprintf(stderr, "Signing failed\n");
								}

								unsigned char *signed_x1 = new unsigned char[sig_len];
								signed_x1 =	&sig_buf[0];

								unsigned int msg2_length;
								msg2_length = (x1_length + sig_len);
								unsigned char *msg2 = new unsigned char[msg2_length];
								memcpy (msg2,x1,x1_length);
								memcpy (msg2 + x1_length,signed_x1,sig_len);

								//cout<<endl<<"Encrypting X1 with session key.."<<endl;
								crypto.setAESKey(k_1,32);
								if((encMsg2Len = crypto.aesEncrypt((const unsigned char*)msg2, msg2_length, &encMsg2)) == -1) {
									fprintf(stderr, "Encryption failed\n");
									return 1;
								}
								//cout<<endl<<"AES encryption with session key successful.."<<endl;
								//cout<<endl<<"Encrypting session key with public key of trusted machine.."<<endl;

								if((encMsgLen = crypto.rsaEncrypt(k_1,32, &encMsg, &ek, &ekl, &iv, &ivl)) == -1) {
									fprintf(stderr, "Encryption failed\n");
								}
								//cout<<endl<<"size of encrypted session key:"<<encMsgLen<<endl;
								//cout<<endl<<"Encrypted session key"<<encMsg<<endl;

								//cout<<endl<<"Building m1..."<<endl;
								unsigned  int m1_length= PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH + encMsgLen + encMsg2Len;
								unsigned char *m_1= new unsigned char[m1_length];
								memcpy (m_1,protocol_step_id,PROTOCOL_ID_LENGTH);
								memcpy (m_1+PROTOCOL_ID_LENGTH,machine_id,MACHINE_ID_LENGTH);
								memcpy (m_1+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH,encMsg,encMsgLen);
								memcpy (m_1+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH+encMsgLen,encMsg2,encMsg2Len);
								//cout<<endl<<"m1 built..."<<endl;

								unsigned int mv1_length= PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH + encMsgLen + encMsg2Len;
								unsigned char *mv_1= new unsigned char[mv1_length];
								memcpy (encMsg,m_1+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH,encMsgLen);


								if((decMsgLen = crypto.rsaDecrypt(encMsg,encMsgLen, ek, ekl, iv, ivl, (unsigned char**)&decMsg)) == -1) {
									fprintf(stderr, "Decryption failed\n");
								}
								unsigned char *kv1 = new unsigned char[32];
								memcpy(kv1,decMsg,32);

								crypto.setAESKey(kv1,32);
								if((decMsg2Len = crypto.aesDecrypt(m_1+PROTOCOL_ID_LENGTH + MACHINE_ID_LENGTH+encMsgLen,encMsg2Len, (unsigned char**)&decMsg2)) == -1) {
									fprintf(stderr, "Decryption failed\n");
									return 1;
								}

								unsigned char *xv1 = new unsigned char[x1_length];
								memcpy(xv1,decMsg2,x1_length);
								unsigned char *certificate = new unsigned char[sig_len];
								memcpy(certificate,decMsg2 + x1_length, sig_len);

								if(i = crypto.verify_alt(mdctx,xv1,x1_length, sig_buf,sig_len,"privkeyServer.pem","certClient.pem")){
									fprintf(stderr, "Signing failed\n");
								}
								else
								{
								verified1 =true;
								}

							if(verified1)
							{
								//cout<<endl<<"Creating Second Log Entry"<<endl;
								unsigned char *log_entry_type = new unsigned char[LOG_ENTRY_TYPE_LENGTH +1];
								log_entry_type = (unsigned char*)"00002"; //log initialiaztion type
								//cout <<endl<<"Log entry initialization:" << log_entry_type<<endl;

								timestamp = std::time(0);
								ts = asctime( localtime(&timestamp) );
								//cout <<endl<< "timestamp:"<<ts<<endl ;

								 data_length = m1_length;
								 memcpy(data,m_1,m1_length);

								//cout<<endl<<"Generating Encryption Key.."<<endl;
								if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}

								unsigned char *key = new unsigned char[32+1];
								memcpy(key,digest,32);
								//cout<<endl<<"Encryption Key Created..."<<endl;

								//cout<<endl<<"Encrypting data with the key..."<<endl;
								crypto.setAESKey(key,32);
								if((encMsg3Len = crypto.aesEncrypt((const unsigned char*)data, data_length, &encMsg3)) == -1) {
									fprintf(stderr, "Encryption failed\n");
									return 1;
								}

								log[log_file_count-1].dl[log[log_file_count-1].no_of_logs]=encMsg3Len;
								log[log_file_count-1].no_of_logs++;

								unsigned int y_0_length = 32;
								if(!(i = crypto.hash(y_0,y_0_length,(unsigned char*)data,data_length,(unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}
								memcpy(y_0,digest,32); //keep updating key of hash chain

								//cout<<endl<<"Creating HMAC..."<<endl;
								if(!(i = crypto.hmac(y_0,y_0_length,a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}
								unsigned char *z_0 = new unsigned char[32];
								memcpy(z_0,digest,32);

								//cout<<endl<<"Creating A_1...."<<endl;
								if(!(i = crypto.hash(a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}
								memcpy(a_0,digest,32);

								//cout<<endl<<"Client has verified the message m1.."<<endl;
								//cout<<endl<<"Creating Log Entry.."<<endl;
								unsigned int log_entry_length = LOG_ENTRY_TYPE_LENGTH + encMsg3Len + y_0_length + Z_0_LENGTH ;
								unsigned char *log_entry = new unsigned char[log_entry_length];
								memcpy (log_entry,log_entry_type,LOG_ENTRY_TYPE_LENGTH);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH,encMsg3,encMsg3Len);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len,y_0,y_0_length);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len+y_0_length,z_0,Z_0_LENGTH);
								//cout<<log_entry_length<<endl;
								//cout<<encMsg3Len<<endl;
								//cout<<y_0_length<<endl;
								//cout<<endl<<log_entry<<endl;
								cout<<endl<<"Log Entry created and added to file"<<endl;

								//cout<<endl<<"Storing log entry.."<<endl;
								log[log_file_count-1].logFile.write((const char*)log_entry,log_entry_length);
								log[log_file_count-1].logFile.write("\nLOGENTRYSEPERATOR\n",strlen("\nLOGENTRYSEPERATOR\n"));
							}
							else
							{
								cout<<endl<<"The entry was not verified"<<endl;
								cout<<endl<<"Creating Second Log Entry"<<endl;

								unsigned char *log_entry_type = new unsigned char[LOG_ENTRY_TYPE_LENGTH +1];
								log_entry_type = (unsigned char*)"00003"; //(abnormal case type)log initialiaztion type
								//cout <<endl<<"Log entry initialization:" << log_entry_type<<endl;

								timestamp = std::time(0);
								ts = asctime( localtime(&timestamp) );
								cout <<endl<< "timestamp:"<<ts<<endl ;
   							    data_length = TIMESTAMP_LENGTH;
								memcpy(data,ts,TIMESTAMP_LENGTH);

								cout<<endl<<"Generating Encryption Key.."<<endl;
								if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}

								unsigned char *key = new unsigned char[32+1];
								memcpy(key,digest,32);
								//cout<<endl<<"Encryption Key Created..."<<endl;

								//cout<<endl<<"Encrypting data with the key..."<<endl;
								crypto.setAESKey(digest,32);
								if((encMsg3Len = crypto.aesEncrypt((const unsigned char*)data, data_length, &encMsg3)) == -1) {
									fprintf(stderr, "Encryption failed\n");
									return 1;
								}

								log[log_file_count-1].dl[log[log_file_count-1].no_of_logs]=encMsg3Len;
								log[log_file_count-1].no_of_logs++;



								unsigned int y_0_length = 32;
								if(!(i = crypto.hash(y_0,y_0_length,(unsigned char*)data,data_length,(unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}
								memcpy(y_0,digest,32); //keep updating key of hash chain

								//cout<<endl<<"Creating HMAC..."<<endl;
								if(!(i = crypto.hmac(y_0,y_0_length,a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}

								unsigned char *z_0 = new unsigned char[32];
								memcpy(z_0,digest,32);

								//cout<<endl<<"Creating A_1...."<<endl;
								if(!(i = crypto.hash(a_0,32,digest,md_len))){
									fprintf(stderr, "Hashing failed\n");
								}
								memcpy(a_0,digest,32);


								unsigned int log_entry_length = LOG_ENTRY_TYPE_LENGTH + encMsg3Len + y_0_length + Z_0_LENGTH ;
								unsigned char *log_entry = new unsigned char[log_entry_length];
								memcpy (log_entry,log_entry_type,LOG_ENTRY_TYPE_LENGTH);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH,encMsg3,encMsg3Len);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len,y_0,y_0_length);
								memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len+y_0_length,z_0,Z_0_LENGTH);
								//cout<<log_entry_length<<endl;
								//cout<<encMsg3Len<<endl;
								//cout<<y_0_length<<endl;
								//cout<<endl<<log_entry<<endl;
								cout<<endl<<"Log Entry created and added to file"<<endl;

								cout<<endl<<"Storing log entry.."<<endl;
								log[log_file_count-1].logFile.write((const char*)log_entry,log_entry_length);
								log[log_file_count-1].logFile.write("\nLOGENTRYSEPERATOR\n",strlen("\nLOGENTRYSEPERATOR\n"));
							}

							}
		  	  	  	  	  	}
		  	  	else
		  	  	  	{
		  	  	  	  cout<<endl<<"A log file by that name exists.. try with another name"<<endl;
		  	  	  	  continue;
		  	  	  	}

		}
	else if(comm1 == "closelog")
			{


				unsigned int x=1,i=0;
				while( x<log_file_count)
				{
					if(log[x].logfile_name == comm2)
						{
						//cout<<endl<<"Creating Log entry about closing file"<<endl;
						unsigned char *log_entry_type = new unsigned char[LOG_ENTRY_TYPE_LENGTH +1];
						log_entry_type = (unsigned char*)"00004"; //(normal close case type)log initialiaztion type
						//cout <<endl<<"Log entry initialization:" << log_entry_type<<endl;

						unsigned char *msg = new unsigned char[32];
						msg = (unsigned char*)"closing log file ";

						std::time_t timestamp = std::time(0);
						char* ts = asctime( localtime(&timestamp) );
						//cout <<endl<< "timestamp:"<<ts<<endl ;
						unsigned int data_length = TIMESTAMP_LENGTH + 17;
						unsigned char* data = new unsigned char[data_length];
						memcpy(data,ts,TIMESTAMP_LENGTH);
						memcpy(data+TIMESTAMP_LENGTH,msg,17);

						//cout<<endl<<"Generating Encryption Key.."<<endl;
						if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_0,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}

						unsigned char *key = new unsigned char[32+1];
						memcpy(key,digest,32);
						//cout<<endl<<"Encryption Key Created..."<<endl;

						//cout<<endl<<"Encrypting data with the key..."<<endl;
						crypto.setAESKey(digest,32);
						if((encMsg3Len = crypto.aesEncrypt((const unsigned char*)data, data_length, &encMsg3)) == -1) {
							fprintf(stderr, "Encryption failed\n");
							return 1;
						}
						log[log_file_count-1].dl[log[log_file_count-1].no_of_logs]=encMsg3Len;
						log[log_file_count-1].no_of_logs++;

						unsigned int y_0_length = 32;
						if(!(i = crypto.hash(y_0,y_0_length,(unsigned char*)data,data_length,(unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}
						memcpy(y_0, digest,32); //keep updating key of hash chain


						//cout<<endl<<"Creating HMAC..."<<endl;
						if(!(i = crypto.hmac(y_0,y_0_length,a_0,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}

						unsigned char *z_0 = new unsigned char[32];
						memcpy(z_0,digest,32);

						//cout<<endl<<"Creating A_1...."<<endl;
						if(!(i = crypto.hash(a_0,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}
						memcpy(a_0,digest,32);

						cout<<endl<<"Creating Log Entry.."<<endl;
						unsigned int log_entry_length = LOG_ENTRY_TYPE_LENGTH + encMsg3Len + y_0_length + Z_0_LENGTH ;
						unsigned char *log_entry = new unsigned char[log_entry_length];
						memcpy (log_entry,log_entry_type,LOG_ENTRY_TYPE_LENGTH);
						memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH,encMsg3,encMsg3Len);
						memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len,y_0,y_0_length);
						memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len+y_0_length,z_0,Z_0_LENGTH);

						log[log_file_count-1].logFile.write((const char*)log_entry,log_entry_length);
						log[log_file_count-1].logFile.write("\nLOGENTRYSEPERATOR\n",strlen("\nLOGENTRYSEPERATOR\n"));

						log[x].logFile.close();
						log[x].isopen = false;
						cout<<endl<<"Closing logfile "<<comm2<<endl;
						break;

						}
					x++;
				}
				if (x == log_file_count)
				{
					cout<<endl<<"could not find such a logFile"<<endl;
					continue;
				}
			}

	else if(comm1 == "append")
		{
			unsigned int len= command1.length()-comm1.length();
			comm2.assign(command1,append_l,len);
			bool flagv=false;

		if(log[log_file_count-1].isopen == true)
			{

			cout<<endl<<"writing: "<<comm2<<endl;
			cout<<endl<<"Creating Log entry about the append"<<endl;
			unsigned char *log_entry_type = new unsigned char[LOG_ENTRY_TYPE_LENGTH +1];

			if(flagv)
			{

				log_entry_type = (unsigned char*)"00006"; //(normal append case type)log initialiaztion type
				//cout <<endl<<"Log entry initialization:" << log_entry_type<<endl;
			}
			else
			{
			log_entry_type = (unsigned char*)"00005"; //(normal append case type)log initialiaztion type
			//cout <<endl<<"Log entry initialization:" << log_entry_type<<endl;
			}
			unsigned char *msg = new unsigned char[comm2.length()];
			for(unsigned int i = 0; i < comm2.length(); i++)
			    {
			      msg[i]=comm2[i];
			    }

			std::time_t timestamp = std::time(0);
			char* ts = asctime( localtime(&timestamp) );
			//cout <<endl<< "timestamp:"<<ts<<endl ;
			unsigned int data_length = TIMESTAMP_LENGTH + comm2.length();
			unsigned char* data = new unsigned char[data_length];
			memcpy(data,ts,TIMESTAMP_LENGTH);
			memcpy(data+TIMESTAMP_LENGTH,msg,comm2.length());

			//cout<<endl<<"Generating Encryption Key.."<<endl;
			if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_0,32,digest,md_len))){
				fprintf(stderr, "Hashing failed\n");
			}

			unsigned char *key = new unsigned char[32+1];
			memcpy(key,digest,32);
			//cout<<endl<<"Encryption Key Created..."<<endl;

			//cout<<endl<<"Encrypting data with the key..."<<endl;
			crypto.setAESKey(digest,32);
			if((encMsg3Len = crypto.aesEncrypt((const unsigned char*)data, data_length, &encMsg3)) == -1) {
				fprintf(stderr, "Encryption failed\n");
				return 1;
			}

			log[log_file_count-1].dl[log[log_file_count-1].no_of_logs]=encMsg3Len;
			log[log_file_count-1].no_of_logs++;

			unsigned int y_0_length = 32;
			if(!(i = crypto.hash(y_0,y_0_length,(unsigned char*)data,data_length,(unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,digest,md_len))){
				fprintf(stderr, "Hashing failed\n");
			}
			memcpy(y_0,digest,32); //keep updating key of hash chain

			//cout<<endl<<"Creating HMAC..."<<endl;
			if(!(i = crypto.hmac(y_0,y_0_length,a_0,32,digest,md_len))){
				fprintf(stderr, "Hashing failed\n");
			}

			unsigned char *z_0 = new unsigned char[32];
			memcpy(z_0,digest,32);

			//cout<<endl<<"Creating A_1...."<<endl;
			if(!(i = crypto.hash(a_0,32,digest,md_len))){
				fprintf(stderr, "Hashing failed\n");
			}
			memcpy(a_0,digest,32);

			//cout<<endl<<"Creating Log Entry.."<<endl;
			unsigned int log_entry_length = LOG_ENTRY_TYPE_LENGTH + encMsg3Len + y_0_length + Z_0_LENGTH ;
			unsigned char *log_entry = new unsigned char[log_entry_length];
			memcpy (log_entry,log_entry_type,LOG_ENTRY_TYPE_LENGTH);
			memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH,encMsg3,encMsg3Len);
			memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len,y_0,y_0_length);
			memcpy (log_entry+LOG_ENTRY_TYPE_LENGTH+encMsg3Len+y_0_length,z_0,Z_0_LENGTH);

			//cout<<endl<<"Storing log entry.."<<endl;
			log[log_file_count-1].logFile.write((const char*)log_entry,log_entry_length);
			log[log_file_count-1].logFile.write("\nLOGENTRYSEPERATOR\n",strlen("\nLOGENTRYSEPERATOR\n"));
			//FUCKING CLOSE IT

			cout<<endl<<"Done appending message to logfile "<<log[log_file_count-1].logfile_name<<endl;
			}
		else
		{
			cout<<endl<<"The file you are trying to append is not open.."<<endl;
			continue;
		}


				}
		else if(comm1 == "exit")
			{
				cout<<endl<<"PEACE!!!"<<endl;
				exit(1);
			}
		else
			{
				printf("You entered an invalid command \n");
			}
	}
	else if(in==3)
			{
				printf("Welcome to Verifier Machine. Enter command \n");
				cin.ignore();
				getline(cin , command);
				cout<<command;
				string delimiter = " ";
				size_t pos=0;
				bool flag3=false;
				int i=0;
				while (i != 2) {
					pos = command.find(delimiter);
					if(i==0){
					comm1 = command.substr(0, pos);
					//cout<<"command: "<<comm1<<endl;
					}
					if(i==1){
					comm2 = command.substr(0, pos);
					//cout<<"filename: "<<comm2<<endl;
					}
					command.erase(0, (pos + delimiter.length()));
					i++;

				}
				//cout<<comm1<<" "<<comm2;

				if(comm1 == "verify")
				{
					if(log[log_file_count-1].isopen == true)
					{
					log[log_file_count-1].logFile.close();

					cout<<endl<<"Sending log file to verifier.."<<endl;
					//cout<<endl<<"Retreiving required encrypted log entry .."<<endl;

					string line;
					ifstream myfile (log[log_file_count-1].logfile_name.c_str(), ios::binary | ios::in);
					int log_entry_no = atoi(comm2.c_str())-1;
					unsigned char *req_log_entry = new unsigned char[2000];

					if (myfile.is_open())
					  {
						int j=0;
						while(j<=log_entry_no)
						{
							if(!(myfile.read((char*)req_log_entry,log[log_file_count-1].dl[j]+LOG_ENTRY_TYPE_LENGTH+64+strlen("\nLOGENTRYSEPERATOR\n"))))
							{
								cout<<endl<<"You have entered wrong entry number.. try again"<<endl;
								flag3=true;
								break;
							}
							//cout<<endl<<j<<" : "<<req_log_entry<<endl;
							j++;
						}

						if(flag3)
							break;

					  }
						if(myfile.is_open())
							myfile.close();


					cout<<endl<<"Verifier creating secure channel between verifier and trusted machine.."<<endl;
					cout<<endl<<"Creating m2.."<<endl;

					const char *log_file_id = new char[LOG_FILE_ID_LENGTH +1];
					std::stringstream ss;
					ss << (log_file_count-1);
					std::string str;
					ss >> str;
					log_file_id = str.c_str();

					unsigned char *data = new unsigned char[log[log_file_count-1].dl[log_entry_no]];
					memcpy(data,req_log_entry+LOG_ENTRY_TYPE_LENGTH,log[log_file_count-1].dl[log_entry_no]);

					int m2_length = PROTOCOL_ID_LENGTH + LOG_FILE_ID_LENGTH + Y_0_LENGTH + Z_0_LENGTH ;
					unsigned char *m2 = new unsigned char[m2_length];
					memcpy(m2,"00003",PROTOCOL_ID_LENGTH);
					memcpy(m2+PROTOCOL_ID_LENGTH,log_file_id,LOG_FILE_ID_LENGTH);
					memcpy(m2+PROTOCOL_ID_LENGTH+LOG_FILE_ID_LENGTH,req_log_entry+LOG_ENTRY_TYPE_LENGTH+log[log_file_count-1].dl[log_entry_no],Y_0_LENGTH);
					memcpy(m2+PROTOCOL_ID_LENGTH+LOG_FILE_ID_LENGTH+Y_0_LENGTH,req_log_entry+LOG_ENTRY_TYPE_LENGTH+log[log_file_count-1].dl[log_entry_no]+Y_0_LENGTH,Z_0_LENGTH);
					//cout<<endl<<m2<<endl;
					//cout<<endl<<"sendng m2 to trusted machine"<<endl;

					unsigned char *y_f = new unsigned char[32];
					memcpy(y_f,m2+PROTOCOL_ID_LENGTH+LOG_FILE_ID_LENGTH,Y_0_LENGTH);
					unsigned char *z_f = new unsigned char[32];
					memcpy(z_f,m2+PROTOCOL_ID_LENGTH+LOG_FILE_ID_LENGTH+Y_0_LENGTH,Z_0_LENGTH);

					//cout<<endl<<"Trusted party calculating a_f from a_0.."<<endl;
					int j=0;
					unsigned char *a_f = new unsigned char[32];
					memcpy(a_f,a_perm,32);
					while(j<=(log_entry_no-1))
					{
						if(!(i = crypto.hash(a_f,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}
						memcpy(a_f,digest,32);
						j++;
					}

					//cout<<endl<<"Checking if values of z_f and y_f are correct.."<<endl;
					if(!(i = crypto.hmac(y_f,Y_0_LENGTH,a_f,32,digest,md_len))){
						fprintf(stderr, "Hashing failed\n");
					}
					unsigned char *z_check = new unsigned char[32];
					memcpy(z_check,digest,32);
					bool flag=true;

					if( strncmp((const char*)z_f,(const char*)z_check,32) == 0)
					{
						//cout<<endl<<"Successfully verified.."<<endl;
						//cout<<endl<<"Sending key of the log entry to Verifier"<<endl;
						//cout<<endl<<"Generating Encryption Key.."<<endl;
						unsigned char *log_entry_type = (unsigned char*)"00005";
						if(!(i = crypto.hash((unsigned char*)log_entry_type,LOG_ENTRY_TYPE_LENGTH,a_f,32,digest,md_len))){
							fprintf(stderr, "Hashing failed\n");
						}

						unsigned char *key = new unsigned char[32+1];
						memcpy(key,digest,32);
						//cout<<endl<<"Encryption Key Created..."<<endl;
						//cout<<endl<<"Sending decryption key to Verifier"<<endl;

						crypto.setAESKey(key,32);
						if((decMsg2Len = crypto.aesDecrypt(data,log[log_file_count-1].dl[log_entry_no], (unsigned char**)&decMsg2)) == -1) {
							fprintf(stderr, "Decryption failed\n");
							return 1;
						}
						cout<<endl<<"The log entry at position "<<log_entry_no<<" is:"<<decMsg2<<endl;

					}
					else
					{
						cout<<endl<<"Failure in verifying hashes.."<<endl;
						continue;
					}


					log[log_file_count-1].logFile.open((log[log_file_count-1].logfile_name).c_str(),std::ios_base::binary|std::ios_base::out | std::ios_base::app);
				  }
					else
					{
					cout<<endl<<"The file you are trying to append is not open.."<<endl;
					continue;
				}
				}
				else if(comm1 == "exit")
						{
							cout<<endl<<"PEACE!!!"<<endl;
							exit(1);
						}
				else
				{
					cout<<endl<<"You have entered incorrect command.."<<endl;
					continue;
				}
			}
	else
	{
		printf("You entered wrong input. Try Again.. \n");

	}


}
return 0;
}

/*
 *



FFFFFFFFFFFFFFFFFFFFFF                        tttt                            lllllll   1111111         tttt
F::::::::::::::::::::F                     ttt:::t                            l:::::l  1::::::1      ttt:::t
F::::::::::::::::::::F                     t:::::t                            l:::::l 1:::::::1      t:::::t
FF::::::FFFFFFFFF::::F                     t:::::t                            l:::::l 111:::::1      t:::::t
  F:::::F       FFFFFFaaaaaaaaaaaaa  ttttttt:::::ttttttt      aaaaaaaaaaaaa    l::::l    1::::1ttttttt:::::tttttttyyyyyyy           yyyyyyy
  F:::::F             a::::::::::::a t:::::::::::::::::t      a::::::::::::a   l::::l    1::::1t:::::::::::::::::t y:::::y         y:::::y
  F::::::FFFFFFFFFF   aaaaaaaaa:::::at:::::::::::::::::t      aaaaaaaaa:::::a  l::::l    1::::1t:::::::::::::::::t  y:::::y       y:::::y
  F:::::::::::::::F            a::::atttttt:::::::tttttt               a::::a  l::::l    1::::ltttttt:::::::tttttt   y:::::y     y:::::y
  F:::::::::::::::F     aaaaaaa:::::a      t:::::t              aaaaaaa:::::a  l::::l    1::::l      t:::::t          y:::::y   y:::::y
  F::::::FFFFFFFFFF   aa::::::::::::a      t:::::t            aa::::::::::::a  l::::l    1::::l      t:::::t           y:::::y y:::::y
  F:::::F            a::::aaaa::::::a      t:::::t           a::::aaaa::::::a  l::::l    1::::l      t:::::t            y:::::y:::::y
  F:::::F           a::::a    a:::::a      t:::::t    tttttta::::a    a:::::a  l::::l    1::::l      t:::::t    tttttt   y:::::::::y
FF:::::::FF         a::::a    a:::::a      t::::::tttt:::::ta::::a    a:::::a l::::::l111::::::111   t::::::tttt:::::t    y:::::::y
F::::::::FF         a:::::aaaa::::::a      tt::::::::::::::ta:::::aaaa::::::a l::::::l1::::::::::1   tt::::::::::::::t     y:::::y
F::::::::FF          a::::::::::aa:::a       tt:::::::::::tt a::::::::::aa:::al::::::l1::::::::::1     tt:::::::::::tt    y:::::y
FFFFFFFFFFF           aaaaaaaaaa  aaaa         ttttttttttt    aaaaaaaaaa  aaaallllllll111111111111       ttttttttttt     y:::::y
                                                                                                                        y:::::y
                                                                                                                       y:::::y
                                                                                                                      y:::::y
                                                                                                                     y:::::y
                                                                                                                    yyyyyyy


 *
 *
 *
 *
 */
