# Differential

### Background
Differential cryptanalysis is a method that was generally attributed by Eli Biham and Adi Shamir in the late 1980s. It's a known-plaintext attack that can be utilized to recover the key used for block cipher. When applied, it helps effectively eliminate the total number of candidates that have to be searched.

### Introduction
First, a primitive block cipher is implemented first for the analysis. The key would be a series of 4-bit text, and each block would be a 4-bit binary message. The process is highly similar to DES, except for each subround the text will not go through a permutation network. The substituition network used for the cipher is

|n |S(n)|
|--|:--:|
|0 |14  |
|1 |2   |
|2 |11  |
|3 |0   |
|4 |4   |
|5 |6   |
|6 |7   |
|7 |15  |
|8 |8   |
|9 |5   |
|10|3   |
|11|9   |
|12|13  |
|13|12  |
|14|1   |
|15|10  |

For visualization, just enter the value for plain text and keys. When the input can be properly encrypted, an analysis would be generated upon request. The site is hosted [here](https://xinxiao.github.io/Differential/); have fun!

### Source
Both the encryption and analysis schema are based on [this article](http://theamazingking.com/crypto-diff.php). Sincerely thanks the author, [Jon King](http://theamazingking.com/index.php), for his contribution.  
