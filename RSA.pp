Program RSAEncryptAndDecrypt_SignAndVerify;

{$H+}

Uses FGInt, FGIntPrimeGeneration, FGIntRSA;

Var
  n, e, d, dp, dq, p, q, phi, one, two, gcd, temp, nilgint : TFGInt;
  test, signature : String;
  ok : boolean;

Begin
 // Enter a random number to generate a prime, i.e.
 // incremental search starting from that number
  writeln('Searching for the first prime...');
  Base10StringToFGInt('102336547456161301', p);
  PrimeSearch(p);
  writeln('Searching for the second prime...');
  Base256StringToFGInt('AEFAFGhdhsgoi!ç"ty!a', q);
  PrimeSearch(q);
 // Compute the modulus
  FGIntMul(p, q, n);
 // Compute p-1, q-1 by adjusting the last digit of the GInt
  p.Number[1] := p.Number[1] - 1;
  q.Number[1] := q.Number[1] - 1;
 // Compute phi(n)
  FGIntMul(p, q, phi);
 // Choose a public exponent e such that GCD(e,phi)=1
 // common values are 3, 65537 but if these aren 't coprime
 // to phi, use the following code
  Base10StringToFGInt('65537', e); // just an odd starting point
  Base10StringToFGInt('1', one);
  Base10StringToFGInt('2', two);
  writeln('Searching for a public exponent...');
  FGIntGCD(phi, e, gcd);
  While FGIntCompareAbs(gcd, one) <> Eq Do
  Begin
    FGIntadd(e, two, temp);
    FGIntCopy(temp, e);
    FGIntGCD(phi, e, gcd);
  End;
  FGIntDestroy(two);
  FGIntDestroy(one);
  FGIntDestroy(gcd);
 // Compute the modular (multiplicative) inverse of e, i.e. the secret exponent (key)
  writeln('Computing secret key...');
  FGIntModInv(e, phi, d);
  FGIntModInv(e, p, dp);
  FGIntModInv(e, q, dq);
  p.Number[1] := p.Number[1] + 1;
  q.Number[1] := q.Number[1] + 1;

  FGIntDestroy(phi);
  FGIntDestroy(nilgint);
 // Now everything is set up to start Encrypting/Decrypting, Signing/Verifying
  test := 'Suppose you were an idiot. And suppose you were a member of Congress. But I repeat myself.';

  writeln('Encrypting... :"Suppose you were an idiot. And suppose you were a member of Congress. But I repeat myself"');
  RSAEncrypt(test, e, n, test);
  writeln('Decrypting...');
  RSADecrypt(test, d, n, Nilgint, Nilgint, Nilgint, Nilgint, test);
 // this Is faster : RSADecrypt(test, nilGInt, n, dp, dq, p, q, test);
  If test = 'Suppose you were an idiot. And suppose you were a member of Congress. But I repeat myself.' Then writeln('Encryption test successfull') Else writeln('Decryption failed');
  test := 'Drugs may lead to nowhere, but at least it''s the scenic route.';
  writeln('Signing...:"Drugs may lead to nowhere, but at least it''s the scenic route."');
  RSASign(test, d, n, Nilgint, Nilgint, Nilgint, Nilgint, signature);
 // this Is faster : RSASign(test, nilgint, n, dp, dq, p, q, signature);
  writeln('Verifying...');
  RSAVerify(test, signature, e, n, ok);
  If ok Then writeln('Signature test successfull') Else writeln('Signature verification failed');

  FGIntDestroy(p);
  FGIntDestroy(q);
  FGIntDestroy(dp);
  FGIntDestroy(dq);
  FGIntDestroy(e);
  FGIntDestroy(d);
  FGIntDestroy(n);
  readln
End.
