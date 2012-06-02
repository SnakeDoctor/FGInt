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

Unit FGIntElGamal;

{$H+}

Interface

Uses SysUtils, FGInt;

Procedure ElGamalEncrypt(P : String; Var g, y, k, modp : TFGInt; Var E : String);
Procedure ElGamalDecrypt(E : String; Var x, p : TFGInt; Var D : String);
Procedure ElGamalSign(M : String; Var p, g, x, k : TFGInt; Var a, b : String);
Procedure ElGamalVerify(Var g, y, p : TFGInt; a, b, M : String; Var ok : Boolean);

Implementation



// Encrypt a string with the ElGamal algorithm,
// P*y^k mod modp = E

Procedure ElGamalEncrypt(P : String; Var g, y, k, modp : TFGInt; Var E : String);
Var
   i, j, modbits : lonGInt;
   PGInt, temp1, temp2, temp3, k1, kt : TFGInt;
   tempstr1, tempstr2, tempstr3 : String;
Begin
   FGIntToBase2String(modp, tempstr1);
   modbits := length(tempstr1);
   convertBase256to2(P, tempstr1);
   tempstr1 := '111' + tempstr1;
   j := modbits - 1;
   While (length(tempstr1) Mod j) <> 0 Do tempstr1 := '0' + tempstr1;
   FGIntCopy(k, k1);
   FGIntRandom1(k1, kt);

   j := length(tempstr1) Div j;
   tempstr2 := '';
   For i := 1 To j Do
   Begin
      tempstr3 := copy(tempstr1, 1, modbits - 1);
      While copy(tempstr3, 1, 1) = '0' Do delete(tempstr3, 1, 1);
      Base2StringToFGInt(tempstr3, PGInt);
      delete(tempstr1, 1, modbits - 1);
      FGIntMontgomeryModExp(y, k1, modp, temp1);
      FGIntMulMod(PGInt, temp1, modp, temp2);
      FGIntdestroy(temp1);
      FGIntMontgomeryModExp(g, k1, modp, temp1);
      FGIntDestroy(PGInt);
      tempstr3 := '';
      FGIntToBase2String(temp2, tempstr3);
      While (length(tempstr3) - modbits) <> 0 Do tempstr3 := '0' + tempstr3;
      tempstr2 := tempstr2 + tempstr3;
      tempstr3 := '';
      FGIntToBase2String(temp1, tempstr3);
      While (length(tempstr3) - modbits) <> 0 Do tempstr3 := '0' + tempstr3;
      tempstr2 := tempstr2 + tempstr3;
      FGIntdestroy(temp1);
      FGIntdestroy(temp2);

      If i <> j Then
      Begin
         FGIntRandom1(kt, temp3);
         FGIntCopy(temp3, kt);
         FGIntMontgomeryModExp(k1, kt, modp, temp3);
         FGIntCopy(temp3, k1);
      End;
   End;

   FGIntDestroy(k1);
   FGIntDestroy(kt);
   While (copy(tempstr2, 1, 1) = '0') Do delete(tempstr2, 1, 1);
   ConvertBase2to256(tempstr2, E);
End;


// Decrypt a string with the ElGamal algorithm,
// E*(y^(-k)) mod p = D

Procedure ElGamalDecrypt(E : String; Var x, p : TFGInt; Var D : String);
Var
   i, j, modbits : longint;
   EGInt, temp1, temp2, temp3 : TFGInt;
   tempstr1, tempstr2, tempstr3 : String;
Begin
   FGIntToBase2String(p, tempstr1);
   modbits := length(tempstr1);
   convertBase256To2(E, tempstr1);
   While copy(tempstr1, 1, 1) = '0' Do delete(tempstr1, 1, 1);
   While (length(tempstr1) Mod (modbits * 2)) <> 0 Do tempstr1 := '0' + tempstr1;

   j := length(tempstr1) Div (modbits * 2);
   tempstr2 := '';
   For i := 1 To j Do
   Begin
      tempstr3 := copy(tempstr1, 1, modbits);
      While copy(tempstr3, 1, 1) = '0' Do delete(tempstr3, 1, 1);
      Base2StringToFGInt(tempstr3, EGInt);
      delete(tempstr1, 1, modbits);
      tempstr3 := copy(tempstr1, 1, modbits);
      While copy(tempstr3, 1, 1) = '0' Do delete(tempstr3, 1, 1);
      Base2StringToFGInt(tempstr3, temp1);
      delete(tempstr1, 1, modbits);

      FGIntMontgomeryModExp(temp1, x, p, temp2);
      FGIntDestroy(temp1);
      FGIntModInv(temp2, p, temp1);
      FGIntDestroy(temp2);

      FGIntMulMod(EGInt, temp1, p, temp3);
      FGIntDestroy(temp1);
      FGIntDestroy(EGInt);
      tempstr3 := '';
      FGIntToBase2String(temp3, tempstr3);
      While (length(tempstr3) Mod (modbits - 1)) <> 0 Do tempstr3 := '0' + tempstr3;
      tempstr2 := tempstr2 + tempstr3;
      FGIntdestroy(temp3);
   End;

   While (Not (copy(tempstr2, 1, 3) = '111')) And (length(tempstr2) > 3) Do delete(tempstr2, 1, 1);
   delete(tempstr2, 1, 3);
   ConvertBase2To256(tempstr2, D);
End;


// Sign a string with the ElGamal algorithm, a = g^k mod p, M = (x * a + k * b) mod (p-1)

Procedure ElGamalSign(M : String; Var p, g, x, k : TFGInt; Var a, b : String);
Var
   temp1, temp2, temp3, pmin1, one : TFGInt;
Begin
   FGIntMontgomeryModExp(g, k, p, temp1);
   FGIntToBase256String(temp1, a);
   Base256StringToFGInt(M, temp2);
   Base10StringToFGInt('1', one);
   FGIntsub(p, one, pmin1);
   FGIntdestroy(one);
   FGIntmod(temp2, pmin1, temp3);
   FGIntCopy(temp3, temp2);
   FGIntMulMod(x, temp1, pmin1, temp3);
   FGIntCopy(temp3, temp1);
   FGIntchangesign(temp1);
   FGIntAddMod(temp2, temp1, pmin1, temp3);
   FGIntCopy(temp3, temp1);
   FGIntdestroy(temp2);
   FGIntModInv(k, pmin1, temp2);
   FGIntMulMod(temp1, temp2, pmin1, temp3);
   FGIntdestroy(temp1);
   FGIntdestroy(temp2);
   FGIntdestroy(pmin1);
   FGIntToBase256String(temp3, b);
   FGIntdestroy(temp3);
End;


// Verify an ElGamal Signature, y = g^x mod p, // Verification: (y^a) * (a^b) mod p = g^M mod p

Procedure ElGamalVerify(Var g, y, p : TFGInt; a, b, M : String; Var ok : Boolean);
Var
   temp1, temp2, temp3, temp4 : TFGInt;
Begin
   Base256StringToFGInt(a, temp1);
   Base256StringToFGInt(b, temp2);
   FGIntMontgomeryModExp(y, temp1, p, temp3);
   FGIntMontgomeryModExp(temp1, temp2, p, temp4);
   FGIntCopy(temp3, temp1);
   FGIntCopy(temp4, temp2);
   FGIntMulMod(temp1, temp2, p, temp3);
   FGIntCopy(temp3, temp1);
   Base256StringToFGInt(M, temp3);
   FGIntMontgomeryModExp(g, temp3, p, temp4);
   FGIntdestroy(temp3);
   FGIntCopy(temp4, temp2);
   If FGIntCompareAbs(temp1, temp2) = Eq Then ok := true Else ok := false;
   FGIntdestroy(temp1);
   FGIntdestroy(temp2);
End;


End.
