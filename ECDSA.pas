{License, info, etc
 ------------------

This implementation is made by me, Walied Othman, to contact me
mail to Walied.Othman@belgacom.net or Triade@ulyssis.org,
always mention wether it 's about the FGInt for Delphi or for
FreePascal, or wether it 's about the 6xs, preferably in the subject line.
If you 're going to use these implementations, at least mention my
name or something and notify me so I may even put a link on my page.
This implementation is freeware and according to the coderpunks'
manifesto it should remain so, so don 't use these implementations
in commercial software.  Encryption, as a tool to ensure privacy
should be free and accessible for anyone.  If you plan to use these
implementations in a commercial application, contact me before
doing so, that way you can license the software to use it in commercial
Software.  If any algorithm is patented in your country, you should
acquire a license before using this software.  Modified versions of this
software must contain an acknowledgement of the original author (=me).
This implementation is available at
http://triade.studentenweb.org

copyright 2000, Walied Othman
This header may not be removed.
}

Unit ECDSA;

{$H+}

Interface

Uses FGInt, ECGFp;


Procedure ECDSASign(M : String; p, a, x, n, k : TFGInt; B : TECPoint; Var r, s : String);
Procedure ECDSAVerify(M, r, s : String; p, a, n : TFGInt; B, Bx : TECPoint; Var Valid : Boolean);

Implementation


// Sign a string M using ECDSA defined on an elliptic curve
// y^2 = x^3 + a*x + b over GF(p), where 4*a^3 + 27*b^2 mod p doesn 't
// equal zero, B is the base point on the curve, x is the secret parameter,
// n is the order of B, and k is random
// The output are the strings r and s

Procedure ECDSASign(M : String; p, a, x, n, k : TFGInt; B : TECPoint; Var r, s : String);
Var
   RP, tempp : TECPoint;
   tempg1, tempg2, tempg3, zero : TFGInt;
   temps : String;
   i : longint;
Begin
   Base2StringToFGInt('0', zero);
   Repeat
      ECPointKMultiple(B, p, a, k, RP);
      FGIntMod(RP.XCoordinate, n, tempg1);
      While FGIntCompareAbs(tempg1, zero) = Eq Do
      Begin
         ECAddPoints(RP, B, p, a, tempp);
         ECPointDestroy(RP);
         ECPointCopy(tempp, RP);
         ECPointDestroy(tempp);
         FGIntDestroy(tempg1);
         FGIntMod(RP.XCoordinate, n, tempg1);
      End;
      FGIntToBase256String(tempg1, r);
      FGIntDestroy(tempg1);
      FGIntToBase2String(n, temps);
      i := length(temps) - 1;
      ConvertBase256To2(M, temps);
      While Length(temps) > i Do delete(temps, length(temps), 1);
      Base2StringToFGInt(temps, tempg1);
      FGIntMulMod(RP.XCoordinate, x, n, tempg2);
      FGIntAddMod(tempg1, tempg2, n, tempg3);
      FGIntDestroy(tempg2);
      FGIntDestroy(tempg1);
      FGIntModInv(k, n, tempg1);
      FGIntMulMod(tempg1, tempg3, n, tempg2);
      FGIntDestroy(tempg3);
      FGIntDestroy(tempg1);
      FGIntToBase256String(tempg2, s);
      FGIntDestroy(tempg2);
      If s = chr(0) Then
      Begin
         ECAddPoints(RP, B, p, a, tempp);
         ECPointDestroy(RP);
         ECPointCopy(tempp, RP);
         ECPointDestroy(tempp);
      End;
   Until s <> chr(0);
   ECPointDestroy(RP);
   FGIntDestroy(zero);
End;


// Verify an ECDSA signature defined on an elliptic curve
// y^2 = x^3 + a*x + b over GF(p), where 4*a^3 + 27*b^2 mod p doesn 't
// equal zero, x is your private parameter as defined above, 
// B is the base point on the curve, Bx is B*x where x is secret,
// n is the order of B, M is the signed message and r and s form
// the signature

Procedure ECDSAVerify(M, r, s : String; p, a, n : TFGInt; B, Bx : TECPoint; Var Valid : Boolean);
Var
   RP, tempp1, tempp2 : TECPoint;
   tempg1, tempg2, tempg3, u1, u2 : TFGInt;
   temps : String;
   i : longint;
Begin
   valid := true;
   If (r = chr(0)) Or (s = chr(0)) Then
   Begin
      valid := false;
      exit;
   End;
   Base256StringToFGInt(r, tempg1);
   If Not (FGIntCompareAbs(tempg1, n) = St) Then
   Begin
      FGIntDestroy(tempg1);
      valid := false;
      exit;
   End;
   FGIntDestroy(tempg1);
   Base256StringToFGInt(s, tempg1);
   If Not (FGIntCompareAbs(tempg1, n) = St) Then
   Begin
      FGIntDestroy(tempg1);
      valid := false;
      exit;
   End;
   FGIntDestroy(tempg1);
   FGIntToBase2String(n, temps);
   i := length(temps) - 1;
   ConvertBase256To2(M, temps);
   While Length(temps) > i Do delete(temps, length(temps), 1);
   Base2StringToFGInt(temps, tempg1);
   Base256StringToFGInt(s, tempg2);
   FGIntModInv(tempg2, n, tempg3);
   FGIntMulMod(tempg3, tempg1, n, u1);
   FGIntDestroy(tempg1);
   FGIntDestroy(tempg2);
   Base256StringToFGInt(r, tempg1);
   FGIntMulMod(tempg1, tempg3, n, u2);
   FGIntDestroy(tempg3);
   ECPointKMultiple(B, p, a, u1, tempp1);
   ECPointKMultiple(Bx, p, a, u2, tempp2);
   FGIntDestroy(u1);
   FGIntDestroy(u2);
   ECAddPoints(tempp1, tempp2, p, a, RP);
   ECPointDestroy(tempp1);
   ECPointDestroy(tempp2);
   FGIntMod(RP.XCoordinate, n, tempg2);
   Valid := (FGIntCompareAbs(tempg1, tempg2) = Eq);
   FGIntDestroy(tempg1);
   FGIntDestroy(tempg2);
   ECPointDestroy(RP);
End;


End.
