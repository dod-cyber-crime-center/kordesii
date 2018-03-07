#include <stdio.h>
#include <string.h>

char string1[] = "Idmmn!Vnsme ";
char string2[] = "K%o\"qmpp{\"Fcqj,\"K%o\"cdpckf\"K\"acl%v\"fm\"vjcv,";
char string3[] = "Wjnf#eojfp#ojhf#bm#bqqlt-#Eqvjw#eojfp#ojhf#b#abmbmb-";
char string4[] = "M$uqmp$i}$nkf$ep$pla$gehaj`ev$begpkv}$slaj$pla}$skqh`j#p$hap$ia$peoa$e$`e}$kbb*";
char string5[] = "Dqm`lvh%lv%d%kjk(uwjum`q%jwbdklvdqljk+";
char string6[] = "O&ngrc&ohucer&vshu*&rnc\x7f&tcgjj\x7f&dsa&kc(";
char string7[] = "Hib'jhuini`'N'tohs'fi'bkbwofis'ni'j~'wfmfjft)''Ohp'ob'`hs'ni'j~'wfmfjft'N'pnkk'ibqbu'lihp)";
char string8[] = "A(\x7fi{(\x7fgflmzafo(\x7f`q(|`m(jidd(cmx|(om||afo(jaoomz(ifl(jaoomz(ifl(|`mf(a|(`a|(em&";
char string13[] = "[vav4`3\x7f||xz}t3rg3j|f?3xzw=";
char string17[] = "@\x7fvc7`r0ar7pxc7\x7frer7~d7qv~{ber7cx7srtengc9";
char string1a[] = "Huot~:oj:nr\x7f:oio{v:ioij\x7fyni4";
char string23[] = "oLVJP\x0f\x03j\x03WKJMH\x03WKJP\x03JP\x03WKF\x03\x41\x46\x44JMMJMD\x03LE\x03\x42\x03\x41\x46\x42VWJEVO\x03\x45QJFMGPKJS\r";
char string27[] = "oBKKH\t\x07j^\x07IFJB\x07NT\x07nIN@H\x07jHISH^F\t\x07~HR\x07LNKKBC\x07J^\x07\x41\x46SOBU\t\x07wUBWFUB\x07SH\x07\x43NB\t";
char string40[] = "\t`!-`3%2)/53n`\x01.$`$/.g4`#!,,`-%`3()2,%9n";
char string46[] = "\x12.#f\x02\x33\"#f\'$/\"#5h";
char string73[] = "'\x1b\x16S\x15\x06\x07\x06\x01\x16S\x04\x1a\x1f\x1fS\x1f\x1c\x1c\x18S\x11\x01\x1a\x14\x1b\x07\x16\x01S\x07\x1c\x1e\x1c\x01\x01\x1c\x04]";
char string75[] = "!\x1d\x10\x06\x10U\x12\x1aU\x01\x1aU\x10\x19\x10\x03\x10\x1b[";
char string77[] = "0\x18W\x16\x1f\x12\x16\x13YW:\x16\x1c\x12W\x1a\x0eW\x13\x16\x0eY";
char string7a[] = "-\x12\x03Z\t\x15Z\t\x1f\x08\x13\x15\x0f\tE";
char string7f[] = "7\x1e\x0c\x0b\x1e_\x13\x1e_\t\x16\x0c\x0b\x1eS_\x1d\x1e\x1d\x06Q";

void encrypt(char *s, char key)
{
	while (*s)
		*s++ ^= key;
}

void decrypt()
{
	encrypt(&string1[0], 0x01);
	encrypt(&string2[0], 0x02);
	encrypt(&string3[0], 0x03);
	encrypt(&string4[0], 0x04);
	encrypt(&string5[0], 0x05);
	encrypt(&string6[0], 0x06);
	encrypt(&string7[0], 0x07);
	encrypt(&string8[0], 0x08);
	encrypt(&string13[0], 0x13);
	encrypt(&string17[0], 0x17);
	encrypt(&string1a[0], 0x1a);
	encrypt(&string23[0], 0x23);
	encrypt(&string27[0], 0x27);
	encrypt(&string40[0], 0x40);
	encrypt(&string46[0], 0x46);
	encrypt(&string73[0], 0x73);
	encrypt(&string75[0], 0x75);
	encrypt(&string77[0], 0x77);
	encrypt(&string7a[0], 0x7a);
	encrypt(&string7f[0], 0x7f);
}

int main()
{
	decrypt();
	printf("%s\n", string1);
	printf("%s\n", string2);
	printf("%s\n", string3);
	printf("%s\n", string4);
	printf("%s\n", string5);
	printf("%s\n", string6);
	printf("%s\n", string7);
	printf("%s\n", string8);
	printf("%s\n", string13);
	printf("%s\n", string17);
	printf("%s\n", string1a);
	printf("%s\n", string23);
	printf("%s\n", string27);
	printf("%s\n", string40);
	printf("%s\n", string46);
	printf("%s\n", string73);
	printf("%s\n", string75);
	printf("%s\n", string77);
	printf("%s\n", string7a);
	printf("%s\n", string7f);

    return 0;
}

