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

Unit FGIntGOSTDSA;

{$H+}

Interface

Uses SysUtils, FGInt;


Procedure GOSTDSAPrimeSearch(q : TFGInt; Var p : TFGInt);
Procedure GOSTDSASign(p, q, a, x : TFGInt; Var k : TFGInt; M : String; Var r, s : String);
Procedure GOSTDSAVerify(p, q, a, y : TFGInt; m, r, s : String; Var ok : Boolean);

Implementation


// Searches for a prime p such that p mod q = 1, when calling
// this procedure, provide a random GInt for p

Procedure GOSTDSAPrimeSearch(q : TFGInt; Var p : TFGInt);
Var
   q2, one, temp1, temp2 : TFGInt;
   ok : boolean;
Begin
   FGIntAdd(q, q, q2);
   FGIntMod(p, q, temp1);
   Base10StringToFGInt('1', one);
   FGIntSub(p, temp1, temp2);
   FGIntDestroy(temp1);
   FGIntAdd(temp2, one, temp1);
   FGIntDestroy(temp2);
   FGIntDestroy(one);
   If (temp1.Number[1] Mod 2) = 0 Then
   Begin
      FGIntadd(temp1, q, temp2);
      FGIntCopy(temp2, temp1);
   End;
   FGIntCopy(temp1, p);

   ok := false;
   While Not ok Do
   Begin
      FGIntadd(p, q2, temp1);
      FGIntCopy(temp1, p);
      FGIntPrimeTest(p, 5, ok);
   End;
   FGIntDestroy(q2);
End;


// p is a prime, (according to the standard, p is i, where i
// ranges from 509 to 512 and from 1020 to 1024, bits long)
// q is a primefactor of p-1, (in the standard q is between 254 and 256 bit)
// a is any number < p-1, such that a^q mod p = 1
// x secret key, a number < q
// k random, less than q, same k must not be used twice and kept secret
// M the string you want to sign
// r,s form the signature

Procedure GOSTDSASign(p, q, a, x : TFGInt; Var k : TFGInt; M : String; Var r, s : String);
Var
   temp1, temp2, temp3, RGInt, SGInt, zero, one : TFGInt;
   zerok : boolean;
Begin
   Base10StringToFGInt('1', one);
   Base10StringToFGInt('0', zero);
   Repeat
      FGIntMontgomeryModExp(a, k, p, temp1);
      FGIntMod(temp1, q, RGInt);
      FGIntdestroy(temp1);
      If FGIntCompareAbs(RGInt, zero) = Eq Then zerok := true Else zerok := false;
      If zerok Then
      Begin
         FGIntDestroy(RGInt);
         FGIntRandom1(k, temp1);
         FGIntCopy(temp1, k);
      End;
   Until Not zerok;
   Base256StringToFGInt(m, temp2);
   FGIntMod(temp2, q, temp1);
   If FGIntCompareAbs(temp1, zero) = Eq Then
   Begin
      FGIntCopy(one, temp2);
   End;
   FGIntDestroy(temp1);
   FGIntMulMod(x, RGInt, q, temp1);
   FGIntMulMod(k, temp2, q, temp3);
   FGIntAddMod(temp1, temp3, q, SGInt);
   FGIntDestroy(temp1);
   FGIntDestroy(temp2);
   FGIntDestroy(temp3);
   FGIntToBase256String(RGInt, r);
   FGIntToBase256String(SGInt, s);
   FGIntDestroy(RGInt);
   FGIntDestroy(SGInt);
   FGIntDestroy(one);
   FGIntDestroy(zero);
End;


// p is a prime, (according to the standard, p is i, where i
// ranges from 509 to 512 and from 1020 to 1024, bits long)
// q is a primefactor of p-1, (in the standard q is between 254 and 256 bit)
// a is any number < p-1, such that a^q mod p = 1
// y = a^x mod p
// m is the signed string, r,s form the signature, ok returns
// true if the signature is valid

Procedure GOSTDSAVerify(p, q, a, y : TFGInt; m, r, s : String; Var ok : Boolean);
Var
   w, u1, u2, v, RGInt, SGInt, temp1, temp2, temp3, zero : TFGInt;
Begin
   Base256StringToFGInt(s, SGInt);
   Base256StringToFGInt(r, RGInt);
   Base256StringToFGInt(m, temp1);
   Base10StringToFGInt('0', zero);
   FGIntMod(temp1, q, temp2);
   If FGIntCompareAbs(zero, temp2) = Eq Then FGIntCopy(zero, v) Else FGIntModInv(temp1, q, v);
   FGIntDestroy(temp1);
   FGIntDestroy(temp2);
   FGIntMulMod(SGInt, v, q, u1);
   FGIntDestroy(SGInt);
   FGIntsub(q, RGInt, temp1);
   FGIntMulMod(v, temp1, q, u2);
   FGIntDestroy(v);
   FGIntDestroy(temp1);
   FGIntMontgomeryModExp(a, u1, p, temp1);
   FGIntMontgomeryModExp(y, u2, p, temp2);
   FGIntMulMod(temp1, temp2, p, temp3);
   FGIntDestroy(temp1);
   FGIntDestroy(temp2);
   FGIntMod(temp3, q, w);
   FGIntDestroy(temp3);
   FGIntDestroy(u1);
   FGIntDestroy(u2);
   If FGIntCompareAbs(RGInt, w) = Eq Then ok := true Else ok := false;
   FGIntDestroy(w);
   FGIntDestroy(RGInt);
End;

End.
