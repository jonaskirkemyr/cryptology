# cryptology-MillerRabin
Build from the same ideas as Fermat test, the Miller-Rabin test can be guaranteed to detect composites if run sufficiently many times.


#Why it works
Sequence: a^u, a^2u,...,a^((2^(v-1))u), a^((2^v)u) % n
If 'n' is prime then Fermat's theorem says that the final value: 

	a^((2^v)u)%n = 1. 

Therefore if 'n' is prime then eiter 

a^u%n=1 

or there's a square root of 1 somewhere in the 'sequence' and this value must be -1. 
If a non-trivial square root of 1 is found, then 'n' is composite.