/*
 * main.cpp
 *
 *  Created on: 5. feb. 2015
 *      Author: jonastn
 */

//TESTING MillerRabin

#include <iostream>
#include "headers/MillerRabin.h"

using namespace std;
int main()
{
	MillerRabin mr(17);  

	States once=mr.isPrime();
	States multiple=mr.runKtimes(4);

	cout<<once<<endl<<multiple<<endl;//0=probable prime, 1=composite

	cin.get();
}


