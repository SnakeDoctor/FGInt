Program ECDSASample;

{$H+}


Uses
   FGInt, ECGFp, ECDSA;

Var
   a, b, p, k, h, x, n, temp, one : TFGInt;
   r, s, T : String;
   g, y : TECPoint;
   ok : boolean;

Begin
// setting up parameters 
   writeln('setting up EC parameters ...');
   Base256StringToFGInt('222222aatzzzznnn', p);
   ok := true;
   While ok Do
   Begin
      FindPrimeGoodCurveAndPoint(p, a, b, h, n, 60, g);
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
   Base256StringToFGInt('ergezam', x);
   ECPointKMultiple(g, p, a, x, y);
   Base10StringToFGInt('63557', k);
   Base2StringToFGInt('1', one);
   FGIntGCD(k, n, temp);
   While Not (FGIntCompareAbs(one, temp) = Eq) Do
   Begin
      FGIntDestroy(temp);
      FGIntAddBis(k, one);
      FGIntGCD(k, n, temp);
   End;
   FGIntDestroy(temp);
   FGIntDestroy(one);

// with all these precautions everything is set up for signing/verifying

   T := 'A black hole is a place where God divided by zero';
   writeln('Signing the following string: ', T);
   ECDSASign(T, p, a, x, n, k, g, r, s);
   writeln('Verifying signature...');
   ECDSAVerify(T, r, s, p, a, n, g, y, ok);
   If ok Then writeln('Verification complete: signature is valid') Else writeln('Signature is not valid');

   FGIntDestroy(p);
   FGIntDestroy(a);
   FGIntDestroy(n);
   FGIntDestroy(k);
   FGIntDestroy(h);
   FGIntDestroy(x);
   ECPointDestroy(g);
   ECPointDestroy(y);
   readln;
End.