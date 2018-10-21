; This project performs encryption or decryption of the message from the input file using
; the Row transposition algorithm. Input .txt file is read into a buffer, and then processed. 
; User can define whether the message should be encrypted or decrypted and how many times. 
; A specific 1-9 digit key is used to alter the characters' positions within the message correspondingly. 
; The result is placed in output file, along with the key, number of iterations performed and altered key word (e/d). 

; begin code

INCLUDE Irvine32.inc ; this library's functions are used for the purpose reading an input file, 
; communication with the user, and writing to an output file
INCLUDE macros.inc

BUFFER_SIZE = 501   ; input buffer size
BUFFER_SIZE2 = 20000 ; velicina bafera u koji se smestaju kriptovani podaci


.data
buffer BYTE BUFFER_SIZE DUP(?) ; original file
buffer1 BYTE BUFFER_SIZE DUP(?); text without space or enter with header
buffer2 BYTE BUFFER_SIZE2 DUP (?); encrypted/decrypted text, all iterations
buffer3 BYTE BUFFER_SIZE2 DUP (?)
filename BYTE 50 DUP(0) ; input file name is inserted by the user and placed here
filenameout BYTE "output.txt", 0 ; this will be the name of the output file
bytesWritten DWORD ? ; used for ouput file declaration 
stringLength DWORD ?
fileHandle  HANDLE ?
str2 BYTE "Bytes written to file [output.txt]: ",0 ; displays how many characters (bytes) are 
; written in the output file
n DWORD 00000000h; ASCII representations of iteration number digits are placed here in altered order
n_bajtova BYTE 0; how many digits does the iteration number have
k_length BYTE 00h; key length
broj_n DWORD 00000000h; decimal number of iterations
operand1 word 1000; used to multiply by 1000
operand2 BYTE 100; used to multiply by 100
operand3 BYTE 10; used to multiply by 10
duzina WORD 00000000h; number of character that the message contains (where space and enter are not included)
podaci BYTE 05h; beginning without e/d
offbuff DWORD ?; place where we start writing new iteration results
offbuff_prev DWORD ?; place where we start reading the current section being processed
offbuff3 DWORD ? ;remains const within an iteration and keeps the first key digit address
offbuff4 DWORD ? ;starts from the first letter of the first virtual block but jumps sequentially to 
;other blocks in order for us to position on the right letter
ukupna_duzina1 WORD 0001h;complete file length (the message is cleared from space and enter)
numit WORD 0000h; current iteration used to compare with broj_n
key_digit BYTE 31h; key digit that is being searched within the key
digit BYTE 00h ; decremented by 1, it helps us determine how many keys are being searched before
;as well as how many jumps do we make before reaching the right block 
x BYTE 00h; what is the number of iterations that we need to perform to locate specific digit within the key
q BYTE 00h; quotient-result of the division of duzina and k_length 
q1 BYTE 00h; quotient+1 that represents the number of characters in bigger blocks
r BYTE 00h; remainder of the division mentioned above
it BYTE 01h ; how much we should move from the key's first digit in order to reach the current key digit we want 
brojac WORD 0000h; we increment this variable each time a new character is found and copied to output buffer
; it also indicates whether we have reached the end of the message, when it becomes equal to duzina
i BYTE 00h ; which character in the block is processed (first, second...)

.code
; svaka od procedura obradjuje slucaj razlicitog broja cifara u n i pretvara ih u decimalni zapis.
; svaka sadrzi and-ovanje sa maskom da bi se izdvojio odgovarajuci bajt (odnosno cifra) koja se 
; zatim dovodi na najnizu poziciju siftovanjem udesno za odgovarajuci broj pozicija, ukoliko je to
; potrebno, mnozi se sa odgovarajucim tezinskim faktorom: 1000, 100 odnosno 10 i sabira u promenljivoj broj_n
case1 PROC c 
push eax
push edx
mov eax, n
mov broj_n, eax
pop edx
pop eax
ret
case1 ENDP

case2 PROC c
push eax
push edx
xor eax, eax
mov eax, n
and eax, 000000FFh
mul operand3
add broj_n, eax
xor eax, eax
mov eax, n
and eax, 0000FF00h
shr eax, 8
add broj_n, eax
pop edx
pop eax
ret
case2 ENDP

case3 PROC c
push eax
push edx
xor eax, eax
mov eax, n
and eax, 000000FFh
mul operand2
add broj_n, eax
xor eax, eax
mov eax, n
and eax, 0000FF00h
shr eax, 8
mul operand3
add broj_n, eax
xor eax, eax
mov eax, n
and eax, 00FF0000h
shr eax, 16
add broj_n, eax
pop edx
pop eax
ret
case3 ENDP

case4 PROC c
push eax
push edx
xor eax, eax
mov eax, n ; u eax smestamo bajtove za obradu
and eax, 000000FFh; izdvajamo poslednji bajt
mul operand1 ; mnozi se sa hiljadu
add broj_n, eax ; doda se u broj iteracija
xor eax, eax
mov eax, n
and eax, 0000FF00h ; isto za stotinu
shr eax, 8
mul operand2
add broj_n, eax
xor eax, eax
mov eax, n
and eax, 00FF0000h ; isto za deseticu
shr eax, 16
mul operand3
add broj_n, eax
xor eax, eax
mov eax, n
and eax, 4278190080 ; moralo ovako :( FF000000h
shr eax, 24
add broj_n, eax
pop edx
pop eax
ret
case4 ENDP

main PROC
; Reading a File                     

; Opens, reads, and displays a text file using
; procedures from Irvine32.lib. 

; Let user input a filename.
	mWrite "Enter an input filename: "
	mov	edx,OFFSET filename
	mov	ecx,SIZEOF filename
	call	ReadString ; f-ji ReadString su potrebni odg sadrzaji r-ra edx i ecx

; Open the file for input.
	mov	edx,OFFSET filename
	call	OpenInputFile
	mov	fileHandle,eax

; Check for errors.
	cmp	eax,INVALID_HANDLE_VALUE		; error opening file?
	jne	file_ok					; no: skip
	mWrite <"Cannot open file",0dh,0ah>
	jmp	quit						; and quit
file_ok:

; Read the file into a buffer.
	mov	edx,OFFSET buffer
	mov	ecx,BUFFER_SIZE
	call	ReadFromFile
	jnc	check_buffer_size			; error reading?
	mWrite "Error reading file. "		; yes: show error message
	call	WriteWindowsMsg
	jmp	close_file
	
check_buffer_size:
	cmp	eax,BUFFER_SIZE			; buffer large enough?
	jb	buf_size_ok				; yes
	mWrite <"Error: Buffer too small for the file",0dh,0ah>
	jmp	quit						; and quit
	
buf_size_ok:	
	mov	buffer[eax],0		; insert null terminator
	mWrite "File size: "
	call	WriteDec			; display file size
	call	Crlf

; Display the buffer.
	mWrite <"Buffer:",0dh,0ah,0dh,0ah>
	mov	edx,OFFSET buffer	; display the buffer
	call	WriteString
	call	Crlf

close_file:
	mov	eax,fileHandle
	call	CloseFile

	mov eax, OFFSET buffer
	mov edx, OFFSET buffer1

	mov ch, 20h


	mov cl, [eax] ; u cl je prvi element originalnog bafera
	mov [edx], cl ; sada taj element prebacimo u bafer1
	add eax, 2; preskacemo space u orig baferu i u eax je adresa prve cifre od n
	add edx, 1; pomerimo se na prvu slobodnu poziciju u baferu1
	mov [edx], ch; stavljamo space u baffer1
	mov ebx, OFFSET n; u ebx je adresa niza u koji upisujemo broj iteracija-pocece da upisuje od najnizeg
	sub ebx, 1; oduzmemo 1 jer u petlji vracamo 1
	input:
	add edx, 1
	add ebx, 1 
	mov cl, [eax] ; u cl je prva cifra
	sub cl, 30h ; u cl je prvi broj
	mov [ebx], cl 
	
	mov [edx], cl; u bafer 1 smestam prvu cifru od n 
	
	add eax, 1 ; pomerimo su unutar niza za 1 mesto
	mov cl, [eax] ; u cl ubacimo sledeci karakter iz bafera
	inc n_bajtova 
	cmp cl, 0Dh ; pitamo da li smo stigli do ODh
	jne input
inc edx ; pomeramo se na prvo slobodno mesto u baferu1
mov cx, 0A0Dh; upisujemo enter new line
mov [edx], cx
add edx, 2; sada tu treba da dodje kljuc
add eax, 2 ; nalazimo se u originalnom baferu na poziciji prve cifre kljuca

cmp n_bajtova, 1 ; ako je broj iteracija jednocifren, ide se na obradu 
; gde se poziva ogovarajuca procedura za taj slucaj
je obrada1
cmp n_bajtova, 2 ; ako je broj iteracija dvocifren, ide se na obradu 
; gde se poziva ogovarajuca procedura za taj slucaj
je obrada2
cmp n_bajtova, 3; ako je broj iteracija trocifren, ide se na obradu 
;gde se poziva ogovarajuca procedura za taj slucaj
je obrada3
call case4; ako nije ni jednocifren ni dvocifren ni trocifren, onda je cetvorocifren i poziva se odgovarajuca procedura
jmp petlja

obrada1:
call case1
jmp petlja

obrada2:
call case2
jmp petlja

obrada3:
call case3
jmp petlja

petlja: ; smesta kljuc u bafer1 (tekst bez razmaka) i racuna duzinu kljuca

	mov cl, [eax] ; u cl se nalazi prva cifra kljuca
	mov [edx], cl; prvu cifru kljuca stavljamo u bafer 
	add k_length, 1; uvecamo duzinu kljuca
	
	inc eax
	inc edx
	mov cl, [eax]
	cmp cl, 0Dh
	jne petlja

mov cx, 0A0Dh
mov [edx], cx
add edx, 2
add eax, 2; na prvom slovu teksta u baferu 
; sad sledi upis teksta, izostavljaju se razmaci i enter-i, racuna se duzina cistog teksta
tekst: 
mov cl, [eax]
inc eax
cmp cl, 20h
je tekst
cmp cl, 0Dh
je tekst
cmp cl, 0Ah
je tekst
cmp cl, 00h ; ako je NULL, stigli smo do kraja teksta, ide se na proveru da li je prvo slovo e ili d
je ed
mov [edx], cl
add edx, 1
add duzina, 1
jmp tekst
ed: ; proveravamo da li je prvi karakter šifrovanje ili dešifrovanje
mov edx, offset buffer1
mov cl, [edx]
cmp cl, 64h
je deljenje
sifrovanje: ;  pripremaju se odgovarajuce promenljive od informativnog znacaja
xor eax, eax
mov ukupna_duzina1, 01h; karakter e
mov podaci, 05h ; razmak i dva entera
mov al, 31h; prva cifra koja se pretrazuje
mov key_digit, al
xor eax, eax
xor edx, edx
mov al, podaci
add al, n_bajtova
add al, k_length
mov podaci, al
mov al, podaci
add ax, ukupna_duzina1 ; sracunat ukupan broj svih karaktera koji se nalaze u baferu1 
;(sa originalnim zaglavljem i porukom ociscenom od razmaka i entera)
add ax, duzina
mov ukupna_duzina1, ax
mov ebx, offset buffer2
mov ax, ukupna_duzina1
mul numit
mov offbuff, edx
shl offbuff, 16
add offbuff, eax
add eax, ebx
mov offbuff, eax
push eax
mov eax, offbuff
xor ecx, ecx
mov cx, ukupna_duzina1
sub eax, ecx
mov offbuff_prev, eax
pop eax
mov edx, offbuff
mov cl, 64h
mov [edx], cl
inc edx
mov eax, offset buffer
inc eax

popunjavanje: ; popunjava se zaglavlje izlaznog bafera
mov cl, [eax]
mov [edx], cl
inc eax
inc edx
push eax
xor eax, eax
mov al, podaci
dec al
mov podaci, al
pop eax
cmp podaci, 0
jne popunjavanje
xor ecx, ecx
mov cl, k_length
kljuc:
xor eax, eax
mov cx, numit
cmp cx, 0
jne ofbuf
mov al, n_bajtova
add eax, 00000004h
add eax, offset buffer1
mov ebx, offset buffer1
mov offbuff_prev, ebx
xor ecx, ecx
mov cl, k_length
jmp compare
ofbuf: ; definise se bafer iz kojeg se cita
mov al, n_bajtova
add eax, 00000004h
add eax, offbuff_prev
xor ecx, ecx ; inicijalizuje se brojacki registar za petlju compare
mov cl, k_length
compare:; trazi se odgovarajuca cifra kljuca u kljucu
mov bl, [eax]
cmp bl, key_digit
je encryption
inc eax
loop compare

encryption:
push eax
xor eax, eax
add al, key_digit
inc al
mov key_digit, al
xor eax, eax
mov al, k_length
add al, 32h ; 32h se dodaje jer se je u finalnoj iteraciji (kad treba da iskocimo) 
;key digit za dva uvecan u odnosu na najveci broj u kljucu
cmp al, key_digit
je provera_n
pop eax
xor ebx, ebx
mov bl, k_length 
add eax, 2
add eax, ebx
mov bl, [eax]
mov [edx], bl
inc edx
nizanje_slova:
xor ebx, ebx
mov bl, k_length
add eax, ebx
push eax
sub eax, offbuff_prev; provera da li smo ispali iz opsega odnosno da li karakter koji smo dohvatili 
; pripada baferu iz kojeg se cita
cmp ax, ukupna_duzina1
jnb kljuc
pop eax
mov bl, [eax]
mov [edx], bl
inc edx
jmp nizanje_slova

provera_n: ;svaki put kad se zavrsi iteracija, broj izvrsenih iteracija numit se inkrementira, pa se 
; poredi sa trazenim brojem iteracija; ako se ovi brojevi poklapaju, iskace se iz obrade i ide se na ispis
push eax
xor eax, eax
add ax, numit
inc eax
mov numit, ax
cmp eax, broj_n
jne sifrovanje
jmp output

deljenje: ; odavde pocinje dekripcija; podeli se duzina poruke bez razmaka i entera sa duzinom kljuca i 
; kolicnik se smesti u promenljivu q, definise se q1 koji je za 1 veci i r koji predstavlja ostatak deljenja
push eax
xor eax, eax
mov ax, duzina
div k_length
mov q, al
mov r, ah
inc al
mov q1, al
pop eax
desifrovanje: ; racunanje potrebnih informacija za desifrovanje
xor eax, eax
mov ukupna_duzina1, 01h
mov podaci, 05h
mov al, 31h
mov key_digit, al
xor eax, eax
xor edx, edx
mov al, podaci
add al, n_bajtova
add al, k_length
mov podaci, al
mov al, podaci
add ax, ukupna_duzina1
add ax, duzina
mov ukupna_duzina1, ax
mov ebx, offset buffer3
mov ax, ukupna_duzina1
mul numit
mov offbuff, edx
shl offbuff, 16
add offbuff, eax
add eax, ebx
mov offbuff, eax
push eax
mov eax, offbuff
xor ecx, ecx
mov cx, ukupna_duzina1
sub eax, ecx
mov offbuff_prev, eax
pop eax
mov edx, offbuff
mov cl, 65h 
mov [edx], cl
inc edx
mov eax, offset buffer
inc eax

popunjavanje1: ;  svaki bafer koji ce predstavljati izlaz tekuce iteracije ce imati najpre upisano zaglavlje sa izmenjenim d u e
mov cl, [eax]
mov [edx], cl
inc eax
inc edx
push eax
xor eax, eax
mov al, podaci
dec al
mov podaci, al
pop eax
cmp podaci, 0
jne popunjavanje1
xor ecx, ecx
mov cl, k_length

kljuc1:				; provera da li citamo iz buffera1 (prva iteracija) ili prethodnog segmenta buffera3 (sve naredne)
; i postavljanje odgovarajucih vrednosti offbuff_prev 
xor eax, eax
mov cx, numit
cmp cx, 0
jne ofbuf1
mov al, n_bajtova
add eax, 00000004h
add eax, offset buffer1
mov ebx, offset buffer1
mov offbuff_prev, ebx
mov offbuff3, eax
add eax, 2
xor ebx, ebx
mov bl, k_length
add eax, ebx
mov offbuff4, eax
mov eax, offbuff3
jmp velika_petlja

ofbuf1:
mov al, n_bajtova
add eax, 00000004h
add eax, offbuff_prev
mov offbuff3, eax
add eax, 2
xor ebx, ebx
mov bl, k_length
add eax, ebx
mov offbuff4, eax
mov eax, offbuff3
; eax na prvom kljucu a u ofbuf4 cuvamo poz prvog slova

velika_petlja: ; pronalazenje i smestanje jednog karaktera iz kriptovane poruke 
; na naredno slobodno mesto u dekriptovanu poruku
xor ecx, ecx
mov cl, 31h
mov key_digit, cl
xor ebx, ebx
mov bl, [eax]
mov digit, bl
xor eax, eax
mov al, digit
sub al, 31h
mov digit, al
mov eax, offbuff3
add eax, 2
xor ebx, ebx
mov bl, k_length
add eax, ebx
mov offbuff4, eax

provera_digita: ; da li je digit stigao do 0
mov bl, digit
cmp bl, 00h
je smesti_slovo
sub bl, 1
mov digit, bl

setovanje_brojaca_loopa:; petlja compare1 ce se ponavljati k_length puta
; ova informacija se mora smestiti u brojacki registar
xor ecx, ecx
mov x, cl
mov cl, k_length
mov eax, offbuff3

compare1:; sluzi za identifikaciju cifre kljuca u kljucu
xor ebx, ebx
mov bl, x
add bl, 1
mov x, bl

mov bl, [eax]
cmp bl, key_digit
je decryption
add eax, 1
loop compare1

decryption:
mov eax, offbuff4
xor ecx, ecx
mov cl, key_digit
add cl, 1
mov key_digit, cl
xor ecx, ecx
mov cl, x
cmp cl, r
jg	qu
qu1:; skok za q+1 (blokovi koji se odnose na prvih r cifara kljuca)
xor ecx, ecx
mov cl, q1
add eax, ecx
mov offbuff4, eax
jmp provera_digita
qu:; skok za q (preostali blokovi)
xor ecx, ecx
mov cl, q
add eax, ecx
mov offbuff4, eax
jmp provera_digita
smesti_slovo:
xor ecx, ecx
mov cl, i ; tek ovde cemo se pomeriti
add eax, ecx
mov bl, [eax]
mov [edx], bl ; smestanje karaktera
inc edx
mov cx, brojac
inc cx
mov brojac, cx
cmp cx, duzina
jne ofbuf3
jmp provera_n1
ofbuf3:; ako nismo sva slova zavrsili
xor eax, eax
mov al, it
add eax, offbuff3
push eax
xor eax, eax
mov al, it
cmp al, k_length
jne continue
; pronasli smo sve karaktere na istoj poziciji u blokovima, idemo opet od prvog broja kljuca
xor eax, eax
mov al, i
inc al
mov i, al
xor eax, eax
inc al
mov it, al
mov eax, offbuff3
jmp velika_petlja
; jos smo u kljucu
continue:
inc al
mov it, al
mov eax, offbuff3
add eax, 2
xor ebx, ebx
mov bl, k_length
add eax, ebx
mov offbuff4, eax
pop eax
jmp velika_petlja

provera_n1: ; provera da li smo stigli do polednje iteracije
push eax
xor eax, eax
add ax, numit
inc eax
mov numit, ax
cmp eax, broj_n
jne resetovanje
jmp output

resetovanje: ; sve relevntne promenljive se resetuju za narednu iteraciju
xor ecx, ecx
mov x, cl
mov i, cl
mov brojac, cx
inc cl
mov it, cl
mov cl, 31h
mov key_digit, cl
jmp desifrovanje

output:	; vrsi se ispis u izlazni fajl i prikazuje se informacija o broju karaktera upisanih u fajl
; Create new text file
mov edx, offset filenameout
call CreateOutputFile
mov fileHandle, eax
;Check errors:
cmp eax, INVALID_HANDLE_VALUE
jne file_ok1
mWrite <"Ne moze se ispisati izlazni fajl", 0dh, 0ah>
jmp close_file1
file_ok1:
mov eax, fileHandle
mov edx, offbuff
xor ecx, ecx
mov cx, ukupna_duzina1
mov stringLength, ecx
mov ecx, stringLength
call WriteToFile
mov bytesWritten,eax ; save return value
call CloseFile

; Display the return value.
mov edx,OFFSET str2 ; "Bytes written"
call WriteString
mov eax,bytesWritten
call WriteDec
call Crlf

jmp quit
close_file1:
mov eax, fileHandle
call CloseFile

quit:
invoke ExitProcess, 0
main ENDP

END main