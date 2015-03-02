#ifndef HOTP_H
#define HOTP_H

#include <string>

class HOTP
{
	private:
		static void truncation(char *&,char *&,int=20);//truncated string, string to truncate, size of truncated string
		
		int computeOffset();
		int computeBinCode(int);//offset

		int length;//length of one-time password
		char * shastr;
		unsigned char *hmac_result;

		int hotp;//the hotp code created
	public:
		HOTP(char *,int=20);//shastr, length of truncate

		void setLength(int);
		int getLength();


};



#endif