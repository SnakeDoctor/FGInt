Program DSASignAndVerify;

{$H+}

Uses FGInt, FGIntPrimeGeneration, FGIntDSA;

Var
  test, r, s : String;
  p, q, g, x, k, y, temp1, temp2, one : TFGInt;
  ok : boolean;

Begin
// searching for primes p,q, where p>q and (p mod q) = 1
  writeln('Searcing for a prime factor...');
  Base10StringToFGInt('12205465', q);
  PrimeSearch(q);
  writeln('Searching for a prime...');
  Base10StringToFGInt('13845131137532411', p);
  DSAPrimeSearch(q, p);

// Generating a good g, meaning g doesn 't equal 1 and g is obtained
// from a random number h, so that g = h^((p-1)/q) mod p
  FGIntCopy(p, temp1);
  temp1.Number[1] := temp1.Number[1] - 1;
  FGIntDiv(temp1, q, temp2);
  FGIntDestroy(temp1);
  Base10StringToFGInt('3420412', g);
  Base10StringToFGInt('1', one);

  writeln('Searching for a generator');
  Repeat
    FGIntRandom1(g, temp1);
    FGIntDestroy(g);
    FGIntCopy(temp1, g);
    FGIntDestroy(temp1);
    FGIntModExp(g, temp2, p, temp1);
    FGIntDestroy(g);
    FGIntCopy(temp1, g);
  Until FGIntCompareAbs(one, g) <> Eq;

  FGIntDestroy(one);
  FGIntDestroy(temp2);

// x is your secret key, random
// k is a random number, the same k must
// not be used twice for a signature
  Base10StringToFGInt('321343208', x);
  Base10StringToFGInt('40215313', k);

// Now we can start signing and verifying
  test := 'come out and play';
  writeln('Signing... : "come out and play"');
  DSASign(p, q, g, x, k, test, r, s);
  FGIntDestroy(k);
  FGIntModExp(g, x, p, y);
  writeln('Verifying...');
  DSAVerify(p, q, g, y, test, r, s, ok);

  If ok Then writeln('test successfull') Else writeln('test failed');

  FGIntdestroy(p);
  FGIntdestroy(q);
  FGIntdestroy(g);
  FGIntdestroy(x);
  FGIntdestroy(k);
  FGIntdestroy(y);
  readln
End.
