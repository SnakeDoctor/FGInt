Program GOSTDSASignAndVerify;

{$H+}

Uses FGInt, FGIntPrimeGeneration, FGIntGOSTDSA;

Var
  p, q, x, a, k, y, temp1, temp2, one : TFGInt;
  test, r, s : String;
  ok : boolean;

Begin
// First we search for 2 primes p and q such that p mod q = 1
  writeln('Searcing for a prime factor...');
  Base10StringToFGInt('9243231', q);
  PrimeSearch(q);
  writeln('Searching for a prime...');
  Base10StringToFGInt('3435423432331', p);
  GOSTDSAPrimeSearch(q, p);
// Generating a good g, meaning g doesn 't equal 1 and g is obtained
// from a random number h, so that g = h^((p-1)/q) mod p
  FGIntCopy(p, temp1);
  temp1.Number[1] := temp1.Number[1] - 1;
  FGIntDiv(temp1, q, temp2);
  FGIntDestroy(temp1);
  Base10StringToFGInt('3420412', a);
  Base10StringToFGInt('1', one);

  writeln('Searching for a generator');
  Repeat
    FGIntRandom1(a, temp1);
    FGIntCopy(temp1, a);
    FGIntModExp(a, temp2, p, temp1);
    FGIntCopy(temp1, a);
  Until FGIntCompareAbs(one, a) <> Eq;

  FGIntDestroy(one);
  FGIntDestroy(temp2);
// x is the secret key, any number less than q
  Base10StringToFGInt('3218', x);
// y = a^x mod p, is part of the public key
  FGIntModExp(a, x, p, y);
// k is a random number less than q, all the above computations have
// to be done only once, k must be different for every signature
  Base10StringToFGInt('402', k);

// now everything is set up to sign and verify
  test := 'Monday is an awful way to spend 1/7th of your life.';
  writeln('Signing... :"Monday is an awful way to spend 1/7th of your life."');
  GOSTDSASign(p, q, a, x, k, test, r, s);
  writeln('Verifying...');
  GOSTDSAVerify(p, q, a, y, test, r, s, ok);
  If ok Then writeln('test successfull') Else writeln('test failed');

  FGIntdestroy(p);
  FGIntdestroy(q);
  FGIntdestroy(a);
  FGIntdestroy(x);
  FGIntdestroy(k);
  FGIntdestroy(y);
  readln
End.
