// ---------------------------------------------------------------------------
// The MIT License (MIT)
//
//Copyright (c) 2015 Jonas Kirkemyr 
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// TOTP.H
// TOTP implementation according to https://tools.ietf.org/html/rfc6238.
// This class requires compiled libraries of openssl [https://www.openssl.org/] to work!
// TOTP inherits HOTP and creates a HMAC based on input secret and current timestamp.
//
// Author: Jonas Kirkemyr <jonas@kirkemyr.no>
// ---------------------------------------------------------------------------

#ifndef TOTP_H
#define TOTP_H

#include "HOTP.h"
#include <ctime>//time()


class TOTP : public HOTP
{
	private:
		static const int T0=0;//start count (unix epoch)

		int timestep;

		int computeCounter();

	public:
		TOTP(int=30);//timestep
		TOTP(unsigned char*,int,int=30);
		TOTP(unsigned char*,int,int,int,const EVP_MD*algo=EVP_sha1());//secret,secretLength,codeLength,timestep,algo

		virtual int getCode();

};

#endif