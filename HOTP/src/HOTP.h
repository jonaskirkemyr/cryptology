#ifndef HOTP_H
#define HOTP_H

#include <string>
#include <cmath>

class HOTP
{
	private:
		static void truncation(unsigned char *&,char *&,int=20);//truncated string, string to truncate, size of truncated string
		
		int computeOffset();
		int computeBinCode(int);//offset

		int length;//length of one-time password
		char * shastr;
	
		unsigned char *hmac_result;
		int resultLength;

	public:
		HOTP(char *,int=6,int=20);//shastr, length of truncate

		void setLength(int);
		int getLength();

		int getCode();


};



#endif