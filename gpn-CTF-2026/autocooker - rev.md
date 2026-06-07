![](./images/Pasted%20image%2020260607011829.png)

This is a 64-bit ELF file which is dynamically linked and not stripped. It was an easy problem.

`main` function:-

```
undefined8 main(int argc,char **argv)

{
  int iVar1;
  undefined4 local_c;
  
  local_c = 0;
  if (1 < argc) {
    iVar1 = strcmp(argv[1],"cooking_class");
    if (iVar1 == 0) {
      local_c = 1;
    }
  }
  printf("%s",HEADER);
  printf("%s\n\n",WELCOME);
  puts("Enter your recipe (flag) you want to cook and confirm with [ENTER]:");
  fgets((char *)&RECIPE,0x40,stdin);
  check_recipe_length();
  FOOD = RECIPE;
  DAT_00404128 = DAT_004040e8;
  DAT_00404130 = DAT_004040f0;
  DAT_00404138 = DAT_004040f8;
  DAT_00404140 = DAT_00404100;
  DAT_00404148 = DAT_00404108;
  DAT_00404150 = DAT_00404110;
  DAT_00404158 = DAT_00404118;
  explain_current_food(local_c);
  salt();
  explain_current_food(local_c);
  fry();
  explain_current_food(local_c);
  trim();
  explain_current_food(local_c);
  mix();
  explain_current_food(local_c);
  taste();
  puts("Congratulations, you \"cooked\" a delicious plate of food!");
  return 0;
}
```

We have to enter our `recipe` when the binary runs which will be our flag. This input gets stored in `RECIPE` using `fgets` function. 
`FOOD` variable copies the value stored in `RECIPE` which is our input.
After that a few lines of `DAT.... = DAT....` all those values are null bytes itself.

![](Pasted%20image%2020260607012247.png)

We can see that in the end there is a line saying that the flag is correctly entered. We will look at all the functions called in between one by one.

`check_recipe_length()` function:-

```
void check_recipe_length(void)

{
  if ((*(char *)((long)&RECIPE + (long)TARGET_LENGTH) == '\0') &&
     (*(char *)((long)&RECIPE + (long)(TARGET_LENGTH + -1)) != '\0')) {
    return;
  }
  puts("Your recipe is too complicated or too simple, I already know it won\'t taste good :(");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

According to this function, length of our input must be `TARGET_LENGTH` which is `0x3D` which is 61, otherwise the code exits with an error.

`taste()` function:-

```
void taste(void)

{
  bool bVar1;
  uint i;
  
  puts("Taste testing...");
  bVar1 = false;
  for (i = 0; i < 0x40; i = i + 1) {
    bVar1 = (bool)(bVar1 | *(char *)((long)&FOOD + (long)(int)i) != DELICIOUS[(int)i]);
  }
  if (bVar1) {
    puts("YUCK!\nOur taste tester thinks your recipe produces bad food, we cannot serve this...");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

First we are setting the value of `bVar1` variable as false. If this variable becomes `true` our code will exit with error code `1`. Which means we want this variable to be always `false`

In the for loop we are iterating over every character of the input stored in `FOOD` and comparing with the value of `DELICIOUS`. If it does not match even once, `bVar1` variable will become `true` which is what we do NOT want!

Looking at the value present in `DELICIOUS` we observe the following bytes

```
[0x0a, 0x0a, 0x0a, 0x0a, 0x7d, 0xdf, 0x5c, 0x4e, 0x5f, 0x9f, 0x99, 0x2c, 0x9f, 0x3e, 0xee, 0x5f,
    0xed, 0x9f, 0x99, 0xee, 0x8f, 0xbc, 0x2e, 0x5f, 0x8f, 0xff, 0xa9, 0x5f, 0x8f, 0x5c, 0xce, 0x5f,
    0x3d, 0xee, 0xbe, 0x99, 0x8d, 0x5f, 0xfc, 0x8f, 0xbe, 0x5f, 0xfd, 0x5c, 0x3d, 0x5f, 0xfe, 0x1c,
    0x3c, 0xb9, 0x5f, 0x6c, 0xfc, 0xfe, 0xcc, 0x5f, 0xb9, 0x1d, 0xce, 0xef, 0x9e, 0x4e, 0xaf, 0xde]
```

Exactly 64 in number.

![](Pasted%20image%2020260607012952.png)

It continues till byte 64.

Which means our final string should match this.
There are more functions in between which we will take a look at one by one.

`salt()` function:-

```
void salt(void)

{
  uint local_c;
  
  puts("Salting...");
  for (local_c = 0; local_c < 0x40; local_c = local_c + 1) {
    *(byte *)((long)&FOOD + (long)(int)local_c) =
         *(byte *)((long)&FOOD + (long)(int)local_c) ^ GRAIN_OF_SALT;
  }
  return;
}
```

Here we are replacing each character of our input stored in `FOOD` with a value `character XOR GRAIN_OF_SALT`.
Value stored in `GRAIN_OF_SALT` is `0xAA` 

![](Pasted%20image%2020260607013321.png)

This can be reversed using the laws of XOR. 

`A ^ B = C, then C ^ B = A`

`fry()` function:-

```
void fry(void)

{
  uint local_c;
  
  puts("Frying...");
  for (local_c = 0; local_c < 0x40; local_c = local_c + 1) {
    *(byte *)((long)&FOOD + (long)(int)local_c) =
         *(char *)((long)&FOOD + (long)(int)local_c) << 4 |
         *(byte *)((long)&FOOD + (long)(int)local_c) >> 4;
  }
  return;
}
```

In this function, we are basically interchanging the higher and lower bits of the character. For example if original character is `0x61` then after this function it will become `0x16`

`trim()` function:-

```
void trim(void)

{
  uint local_c;
  
  puts("Oops, it burned :(\nCutting off the burnt bits...");
  for (local_c = TARGET_LENGTH; local_c < 0x40; local_c = local_c + 1) {
    *(byte *)((long)&FOOD + (long)(int)local_c) = *(byte *)((long)&FOOD + (long)(int)local_c) & 0xf;
  }
  return;
}
```

In earlier function we know that `TARGET_LENGTH` has `0x3d` stored which means 61. In this loop, we are looping 61, 62 and 63 character.
We perform logical `AND` on the character with `0xf` which means only the high nibble will be turning to `0`. Example `0xAA` will become `0x0A`

`mix()` function:-

```
void mix(void)

{
  undefined1 local_58 [56];
  undefined8 local_20;
  uint local_c;
  
  puts("Mixing...");
  local_20 = DAT_00404158;
  for (local_c = 0; local_c < 0x40; local_c = local_c + 1) {
    *(undefined1 *)((long)&FOOD + (long)(int)local_c) =
         *(undefined1 *)((long)&local_20 + (7 - (long)(int)local_c));
  }
  return;
}
```

This function performs a full string reversal on the 64 byte data string.

To reverse the entire thing and find the flag, we have to do the following:-
- Take `DELICIOUS` string as the starting point
- Reverse the string
- Ignore thhe trim function since it does transformation on bytes after 61 and our flag string will be exactly 61 bytes long
- Then to reverse the `fry` function, we will swap the high 4 bits with low 4 bits of every character
- To reverse the `salt` function, we will again `XOR` each character with `0xAA`

The following python script will solve this taking reference of `DELICIOUS` string:-

```
# 1. The final DELICIOUS bytes checked by taste()
delicious = bytes([0x0a, 0x0a, 0x0a, 0x0a, 0x7d, 0xdf, 0x5c, 0x4e, 0x5f, 0x9f, 0x99, 0x2c, 0x9f, 0x3e, 0xee, 0x5f,
    0xed, 0x9f, 0x99, 0xee, 0x8f, 0xbc, 0x2e, 0x5f, 0x8f, 0xff, 0xa9, 0x5f, 0x8f, 0x5c, 0xce, 0x5f,
    0x3d, 0xee, 0xbe, 0x99, 0x8d, 0x5f, 0xfc, 0x8f, 0xbe, 0x5f, 0xfd, 0x5c, 0x3d, 0x5f, 0xfe, 0x1c,
    0x3c, 0xb9, 0x5f, 0x6c, 0xfc, 0xfe, 0xcc, 0x5f, 0xb9, 0x1d, 0xce, 0xef, 0x9e, 0x4e, 0xaf, 0xde]) # Note: fixed '1c' to '0x1c' for valid python syntax

# 2. Undo mix() -> Reverse the entire array
step1 = delicious[::-1]

# 3. Undo fry() -> Swap nibbles for each byte
step2 = bytearray()
for b in step1:
    swapped = ((b << 4) & 0xF0) | ((b >> 4) & 0x0F)
    step2.append(swapped)

# 4. Undo salt() -> XOR with 0xAA
flag_bytes = bytearray()
for b in step2:
    flag_bytes.append(b ^ 0xAA)

# Print the first 61 characters (TARGET_LENGTH)
print("Flag:", flag_bytes[:61].decode('ascii', errors='ignore'))
```

Flag: `GPNCTF{1_fEel_1ikE_you_ARe_r3ADy_FoR_0UR_HaRD3St_DISh3S_NoW}`


