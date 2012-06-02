Program ElGamalSignAndVerify_EncryptAndDecrypt;

{$H+}

Uses FGInt, FGIntPrimeGeneration, FGIntElGamal;

Var
  p, phi, g, x, y, k, one, two, temp, gcd : TFGInt;
  test, a, b : String;
  ok : boolean;

Begin
 // Enter a random number to generate a prime, i.e.
 // incremental search starting from that number
  writeln('Searching for a prime...');
  Base10StringToFGInt('10233654741234567890123456789056161301', p);
  PrimeSearch(p);
 // Compute phi(p)
  FGIntCopy(p, phi);
  phi.Number[1] := phi.Number[1] - 1;
 // x is your secret key
  Base10StringToFGInt('11212312341234512345612345671203', x);
 // g is any number
  Base10StringToFGInt('21316465461203', g);
 // k a random value, such that GCD(k,phi)=1, NEVER use the same k twice
  Base10StringToFGInt('1131', k);

  Base10StringToFGInt('1', one);
  Base10StringToFGInt('2', two);
  writeln('Searching for the random parameter...');
  FGIntGCD(phi, k, gcd);
  While FGIntCompareAbs(gcd, one) <> Eq Do
  Begin
    FGIntDestroy(gcd);
    FGIntadd(k, two, temp);
    FGIntCopy(temp, k);
    FGIntGCD(phi, k, gcd);
  End;
  FGIntDestroy(two);
  FGIntDestroy(one);
  FGIntDestroy(gcd);
 // Now everything is set up to sign and verify
  test := 'eagles may soar high, but weasles do not get sucked into jet engines';

  writeln('Signing... : "eagles may soar high, but weasles do not get sucked into jet engines"');
  ElGamalSign(test, p, g, x, k, a, b);
 // a and b form the signature
 // compute a public key from the secret key: g^x = mod p
  FGIntModExp(g, x, p, y);
  writeln('Verifying...');
  ElGamalVerify(g, y, p, a, b, test, ok);
  If ok Then writeln('Signature test successfull') Else writeln('Signature verification failed');

// k a random number, never use the same k twice
  Base10StringToFGInt('106511234567890123123412345', k);

// Now everything is set up to start encrypting and decrypting
  test := 'A conscience is what hurts when all your other parts feel so good.';
  writeln('Encrypting... : "A conscience is what hurts when all your other parts feel so good."');
  ElGamalEncrypt(test, g, y, k, p, test);
  writeln('Decrypting...');
  ElGamalDecrypt(test, x, p, test);
  If test = 'A conscience is what hurts when all your other parts feel so good.' Then writeln('Encryption test successfull') Else writeln('Decryption failed');

  FGIntDestroy(p);
  FGIntDestroy(g);
  FGIntDestroy(x);
  FGIntDestroy(y);
  FGIntDestroy(k);
  readln
End.
