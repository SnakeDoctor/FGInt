Program ECElGamalSample;

{$H+}

Uses
   crt, FGInt, ECGFp, ECElGamal;


Var
   a, b, p, k, x, n, h : TFGInt;
   S, T : String;
   g, y : TECPoint;
   ok : boolean;

Begin
// First we generate a prime, this will determine our underlying prime field
   writeln('Setting up parameters....');
   Base256StringToFGInt('gxTHtzzzzznnn', p);
   ok := true;
   While ok Do
   Begin
      FindPrimeGoodCurveAndPoint(p, a, b, h, n, 50, g);
      IsECSuperSingular(p, a, b, ok);
      If ok Then
      Begin
         FGIntDestroy(a);
         FGIntDestroy(b);
         FGIntDestroy(h);
         FGIntDestroy(n);
         ECPointDestroy(g);
      End;
   End;
// x is a private parameter
   Base2StringToFGInt('10101001011000011101', x);
// k is a random parameter
   Base256StringToFGInt('AEfz32QSD', k);
// y is another public parameter, y = x * g
   ECPointkmultiple(g, p, a, x, y);
   S := 'peek-a-boo, I c u';
   writeln('Encrypting: ', S);
// Now everything is set for encryption and decryption
   ECElGamalEncrypt(S, p, a, b, k, g, y, true, T);
   S := '';
   writeln('Decrypting... ');
   ECElGamalDecrypt(T, p, a, b, x, S);
   writeln('Result: ', S);
   FGIntDestroy(k);
   FGIntDestroy(x);
   FGIntDestroy(a);
   FGIntDestroy(b);
   FGIntDestroy(h);
   FGIntDestroy(n);
   ECPointDestroy(g);
   readln
End.
